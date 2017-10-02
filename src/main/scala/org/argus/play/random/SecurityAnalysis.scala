package org.argus.play.random

import java.io.FileWriter

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile._
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.plugin.ApiMisuseResult
import org.argus.amandroid.plugin.apiMisuse.{CryptographicMisuse, HideIcon, SSLTLSMisuse}
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.jawa.alir.taintAnalysis.TaintPath
import org.argus.jawa.core.util._
import org.argus.jawa.core.{MsgLevel, PrintReporter}
import org.argus.play.cli.util.CliLogger

import scala.language.postfixOps
import scala.concurrent.duration._

/**
  * Created by fgwei on 3/27/17.
  */
object SecurityAnalysis {
  def apply(sourcePath: String, outputPath: String, checkers: IList[Int], startNum: Int, endNum: Int, timeout: Int): Unit = {
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
      if (i >= startNum && i < endNum) {
        println(i + " of " + decs.size + ":####" + fileUri + "####")
        if (ApkGlobal.isDecompilable(fileUri)) {
          doAnalysis(i, fileUri, outputUri, checkers)
        }
      }
    }
  }

  def doAnalysis(i: Int, fileUri: FileResourceUri, outputUri: FileResourceUri, checkers: IList[Int]): Unit = {
    var outApkUri: FileResourceUri = null
    try {
      /******************* Load given Apk *********************/
      println("Start Loading Apk...")
      val reporter = new PrintReporter(MsgLevel.NO)
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
      val yard = new ApkYard(reporter)
      println("  Decompiling...")
      ApkDecompiler.decompile(fileUri, settings)
      println("  Loading...")
      val apk = new ApkGlobal(ApkModel(fileUri, settings.strategy.layout), reporter)
      apk.load()

      outApkUri = apk.model.layout.outputSrcUri

      val misuseReports: MSet[ApiMisuseResult] = msetEmpty

      /******************* Light-weight checkers *********************/
      if(checkers.contains(1)) {
        println("Light-weight checker HideIcon.")
        val man = AppInfoCollector.analyzeManifest(reporter, FileUtil.appendFileName(outApkUri, "AndroidManifest.xml"))
        val mainComp = man.getIntentDB.getIntentFmap.find{ case (_, fs) =>
          fs.exists{ f =>
            f.getActions.contains("android.intent.action.MAIN") && f.getCategorys.contains("android.intent.category.LAUNCHER")
          }
        }.map(_._1)
        if(mainComp.isDefined) {
          val checker1 = new HideIcon(mainComp.get)
          misuseReports += checker1.check(apk, None)
        }
      }
      if(checkers.contains(2)) {
        println("Light-weight checker CryptographicMisuse.")
        val checker2 = new CryptographicMisuse
        misuseReports += checker2.check(apk, None)
      }
      if(checkers.contains(3)) {
        println("Light-weight checker SSLTLSMisuse.")
        val checker3 = new SSLTLSMisuse
        misuseReports += checker3.check(apk, None)
      }

      val taintReports: MMap[String, MSet[TaintPath]] = mmapEmpty

      if(checkers.contains(4) || checkers.contains(5)) {
        println("  Collecting Info...")
        AppInfoCollector.collectInfo(apk, resolveCallBack = true)
        yard.addApk(apk)
        println("Apk Loaded!")

        /** ***************** Perform component based analysis *********************/
        val report_fileuri = FileUtil.appendFileName(outputUri, "report.txt")
        val writer = new FileWriter(FileUtil.toFile(report_fileuri), true)
        val lines = (apk.getApplicationClassCodes ++ apk.getUserLibraryClassCodes).values.map(_.code.split("[\n|\r]").length).sum
        println("Component based analysis started!")
        timed(fileUri, lines, writer) {
          ComponentBasedAnalysis.prepare(Set(apk))(2 minutes)
        }
        writer.close()
        val cba = new ComponentBasedAnalysis(yard)
        cba.phase1(Set(apk))
        println("Component based analysis done!")

        /** ***************** Heavy-weight checkers *********************/
        if(checkers.contains(4)) {
          println("Heavy-weight checker CommunicationLeakage.")
          val checker4 = new CommunicationSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
          apk.getIDDGs foreach { case(typ, iddg) =>
            apk.getIDFG(typ) match {
              case Some(idfg) =>
                taintReports.getOrElseUpdate("CommunicationLeakage", msetEmpty) ++= AndroidDataDependentTaintAnalysis(yard, iddg, idfg.ptaresult, checker4).getTaintedPaths
              case None => isetEmpty
            }
          }
        }
        if(checkers.contains(5)) {
          println("Heavy-weight checker IntentInjection.")
          val checker5 = new IntentInjectionSourceAndSinkManager(AndroidGlobalConfig.settings.injection_sas_file)
          apk.getIDDGs foreach { case(typ, iddg) =>
            apk.getIDFG(typ) match {
              case Some(idfg) =>
                taintReports.getOrElseUpdate("IntentInjection", msetEmpty) ++= AndroidDataDependentTaintAnalysis(yard, iddg, idfg.ptaresult, checker5).getTaintedPaths
              case None => isetEmpty
            }
          }
        }
      }

      /** ***************** Write report *********************/
      println("Writing Report.")
      val report_fileuri = FileUtil.appendFileName(outputUri, "report" + i + ".ini")
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
        taintReports.foreach { case (checkerName, paths) =>
          if(paths.nonEmpty) writer.write("!")
          writer.write(checkerName + ":\n")
          if(paths.isEmpty) writer.write("  No taint path found.\n")
          paths.foreach { path =>
            if(path.getPath.size <= 10)
              writer.write(path.toString)
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
        CliLogger.logError(FileUtil.toFile(outputUri), "Error: ", e)
    } finally {
      if (outApkUri != null) {
        ConverterUtil.cleanDir(outApkUri)
        FileUtil.toFile(outApkUri).delete()
      }
    }
  }

  private[this] def timed[T](label: String, line: Int, log: FileWriter)(t: => T): Unit = {
    val start = System.nanoTime
    try t
    catch {
      case _: Exception =>
    }
    val elapsed = System.nanoTime - start
    log.write(label + " " + line + " " + (elapsed/1e9) + "\n")
  }
}
