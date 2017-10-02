package org.argus.play.random

import java.io.{File, FileWriter}

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util._
import org.argus.play.cli.util.CliLogger

import scala.io.Source
import scala.language.postfixOps

/**
  * Created by fgwei on 3/22/17.
  */
object CountComponentNum {
  def apply(sourcePath: String, outputPath: String, file: String): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    val map: MMap[String, String] = mmapEmpty
    for(line <- Source.fromFile(file).getLines()) {
      val parts = line.split(" ")
      var secs = parts(1)
      secs = secs.replace("s", "")
      map(parts.head) = secs
    }

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      val fileName = FileUtil.toFile(fileUri).getName
      if(map.contains(fileName)) {
        i += 1
        println(i + " of " + map.size + ":####" + fileUri + "####")
        var outApkUri: FileResourceUri = null
        try {
          /******************* Load given Apk *********************/
          val reporter = new DefaultReporter
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout)
          val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
          val yard = new ApkYard(reporter)
          val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
          outApkUri = apk.model.layout.outputSrcUri
          val manifestUri = FileUtil.appendFileName(outApkUri, "AndroidManifest.xml")
          val mfp = AppInfoCollector.analyzeManifest(reporter, manifestUri)

          /******************* Write report *********************/
          val report_fileuri = FileUtil.appendFileName(outputUri, "report.txt")
          val writer = new FileWriter(FileUtil.toFile(report_fileuri), true)
          try {
            writer.write(fileName + " " + map(fileName) + " " + mfp.getComponentInfos.size + " " + apk.getApplicationClassCodes.values.map(_.code.split("[\n|\r]").length).sum + "\n")
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
