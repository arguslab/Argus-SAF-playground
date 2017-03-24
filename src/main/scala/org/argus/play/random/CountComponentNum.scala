package org.argus.play.random

import java.io.{File, FileWriter}

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, ConverterUtil}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util.MyFileUtil
import org.argus.play.cli.util.CliLogger
import org.sireum.util._

import scala.io.Source

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
      map(parts.head) = parts(1).substring(0, parts(1).length - 1)
    }

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      val fileName = FileUtil.toFile(fileUri).getName
      if(map.contains(fileName)) {
        i += 1
        println(i + " of " + map.size + ":####" + fileUri + "####")
        var outApkUri: FileResourceUri = ApkFileUtil.getOutputUri(fileUri, outputUri)
        try {
          /** ***************** Load given Apk *********************/
          val outUri = ApkDecompiler.decodeApk(fileUri, outputUri, forceDelete = true, createFolder = true, "src")
          val manifestUri = MyFileUtil.appendFileName(outUri, "AndroidManifest.xml")
          val mfp = AppInfoCollector.analyzeManifest(new DefaultReporter, manifestUri)

          /** ***************** Write report *********************/
          val report_fileuri = MyFileUtil.appendFileName(outputUri, "report.txt")
          val writer = new FileWriter(FileUtil.toFile(report_fileuri), true)
          try {
            writer.write(fileName + " " + map(fileName) + " " + mfp.getComponentInfos.size + "\n")
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
