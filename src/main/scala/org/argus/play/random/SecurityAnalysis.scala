package org.argus.play.random

import java.io.{File, FileWriter}

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile.{ApkDecompiler, ConverterUtil, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.dedex.DecompileTimer
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.amandroid.plugin.ApiMisuseResult
import org.argus.amandroid.plugin.apiMisuse.{CryptographicMisuse, HideIcon, SSLTLSMisuse}
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceAnalysis
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.{Constants, MsgLevel, PrintReporter}
import org.argus.jawa.core.util.MyFileUtil
import org.argus.play.cli.util.CliLogger
import org.sireum.util._

import scala.language.postfixOps
import scala.concurrent.duration._

/**
  * Created by fgwei on 3/27/17.
  */
object SecurityAnalysis {
  def apply(sourcePath: String, outputPath: String, checkers: IList[Int], startNum: Int): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    if(checkers.isEmpty) {
      println("Checkers is empty. Stop analysis.")
      return
    }

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      i += 1
      if (i >= startNum) {
        println(i + " of " + decs.size + ":####" + fileUri + "####")
        if (ApkGlobal.isDecompilable(fileUri)) {
          var outApkUri: FileResourceUri = null
          try {
            /******************* Load given Apk *********************/
            println("Start Loading Apk...")
            val reporter = new PrintReporter(MsgLevel.NO)
            val layout = DecompileLayout(outputUri)
            val settings = DecompilerSettings(
              AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri),
              dexLog = false, debugMode = false, removeSupportGen = true,
              forceDelete = true, Some(new DecompileTimer(5 minutes)), layout)
            val yard = new ApkYard(reporter)
            println("  Decompiling...")
            val (outUri, srcs, _) = ApkDecompiler.decompile(fileUri, settings)
            println("  Loading...")
            val apk = new ApkGlobal(ApkModel(fileUri, outUri, srcs), reporter)
            srcs foreach {
              src =>
                val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
                if(FileUtil.toFile(fileUri).exists()) {
                  //store the app's jawa code in AmandroidCodeSource which is organized class by class.
                  apk.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
                }
            }
            println("  Collecting Info...")
            AppInfoCollector.collectInfo(apk, outUri)
            yard.addApk(apk)
            outApkUri = apk.model.outApkUri
            println("Apk Loaded!")

            val misuseReports: MSet[ApiMisuseResult] = msetEmpty
            val taintReports: MMap[String, Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterproceduralDataDependenceAnalysis.Edge]]] = mmapEmpty

            /******************* Light-weight checkers *********************/
            if(checkers.contains(1)) {
              println("Light-weight checker HideIcon.")
              val checker1 = new HideIcon
              misuseReports += checker1.check(apk, None)
            }
            if(checkers.contains(3)) {
              println("Light-weight checker SSLTLSMisuse.")
              val checker3 = new SSLTLSMisuse
              misuseReports += checker3.check(apk, None)
            }

            if(checkers.contains(2) || checkers.contains(4) || checkers.contains(5)) {
              /** ***************** Perform component based analysis *********************/
              println("Component based analysis started!")
              ComponentBasedAnalysis.prepare(Set(apk))(AndroidGlobalConfig.settings.timeout minutes)
              val cba = new ComponentBasedAnalysis(yard)
              cba.phase1(Set(apk))
              val iddResult = cba.phase2(Set(apk))
              println("Component based analysis done!")

              /** ***************** Heavy-weight checkers *********************/
              if(checkers.contains(2)) {
                println("Heavy-weight checker CryptographicMisuse.")
                val checker2 = new CryptographicMisuse
                apk.getIDFGs.foreach { case (_, idfg) =>
                  misuseReports += checker2.check(apk, Some(idfg))
                }
              }
              if(checkers.contains(4)) {
                println("Heavy-weight checker CommunicationLeakage.")
                val checker4 = new CommunicationSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
                val tar = cba.phase3(iddResult, checker4)
                taintReports("CommunicationLeakage") = tar
              }
              if(checkers.contains(5)) {
                println("Heavy-weight checker IntentInjection.")
                val checker5 = new IntentInjectionSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
                val tar = cba.phase3(iddResult, checker5)
                taintReports("IntentInjection") = tar
              }
            }

            /** ***************** Write report *********************/
            println("Writing Report.")
            val report_fileuri = MyFileUtil.appendFileName(outputUri, "report" + i + ".ini")
            val writer = new FileWriter(FileUtil.toFile(report_fileuri), false)
            try {
              writer.write(apk.model.getAppName + "\n\n")
              misuseReports.foreach { r =>
                if(r.misusedApis.nonEmpty) writer.write("!")
                writer.write(r.checkerName + ":\n")
                if(r.misusedApis.isEmpty) writer.write("  No misuse.\n")
                r.misusedApis.foreach {
                  case ((sig, line), des) => writer.write("  " + sig + " " + line + " : " + des + "\n")
                }
              }
              taintReports.foreach { case (checkerName, tar) =>
                if(tar.isDefined) {
                  if(tar.get.getTaintedPaths.nonEmpty) writer.write("!")
                  writer.write(checkerName + ":\n")
                  if(tar.get.getTaintedPaths.isEmpty) writer.write("  No taint path found.\n")
                  tar.get.getTaintedPaths.foreach { path =>
                    writer.write(path.toString)
                  }
                }
              }
            } catch {
              case e: Exception =>
                throw e
            } finally {
              writer.close()
            }
          } catch {
            case e: Throwable =>
              CliLogger.logError(new File(outputPath), "Error: ", e)
          } finally {
            if (outApkUri != null) {
              ConverterUtil.cleanDir(outApkUri)
              FileUtil.toFile(outApkUri).delete()
            }
          }
        }
      }
    }
  }
}
