package org.argus.play.random

import java.io.FileWriter

import org.apache.commons.lang3.StringUtils
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.jawa.core.util.MyFileUtil
import org.argus.jawa.core.{DefaultReporter, Global, JawaType, Signature}
import org.argus.play.util.Utils
import org.ini4j.Wini
import org.sireum.util._

/**
  * Generate the statistics of native lib usage from given dataset.
  */
object NativeStatistics {
  def apply(sourcePath: String, outputPath: String): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    /******************* Get all Apks *********************/
    val decs = ApkFileUtil.getDecompileableFiles(pathUri)
    var i = 0
    decs foreach { fileUri =>
      i += 1
      println(i + " of " + decs.size + ":####" + fileUri + "####")
      var outApkUri: FileResourceUri = null
      try {
        /** ***************** Load given Apk *********************/
        val reporter = new DefaultReporter
        // Global is the class loader and class path manager
        val global = new Global(fileUri, reporter)
        global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
        val layout = DecompileLayout(outputUri)
        val settings = DecompilerSettings(
          AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri),
          dexLog = false, debugMode = false, removeSupportGen = true,
          forceDelete = false, None, layout)
        val apk = Utils.loadApk(fileUri, settings, global)
        outApkUri = apk.outApkUri

        /** ***************** Get all .so files *********************/
        val so_files = FileUtil.listFiles(apk.outApkUri, ".so", recursive = true)

        /** ***************** Get all native methods *********************/
        val classes = global.getApplicationClasses
        // be careful this takes some time
        val native_methods = classes.map(_.getDeclaredMethods.filter(_.isNative).map(_.getSignature)).fold(isetEmpty)(_ ++ _)

        /** ***************** Get all Runtime.exec *********************/
        var execs = 0
        global.getApplicationClassCodes.foreach { case (_, sf) =>
          execs += StringUtils.countMatches(sf.code, "`java.lang.Runtime.exec`")
        }

        /** ***************** Get NativeActivities *********************/
        val native_acts = apk.getComponentInfos.map(_.compType).filter{ a =>
          global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(a, new JawaType("android.app.NativeActivity"))
        }

        /** ***************** Write report *********************/
        val report_fileuri = MyFileUtil.appendFileName(outputUri, "report" + i + ".ini")
        val writer = new FileWriter(FileUtil.toFile(report_fileuri), false)
        try {
          writer.write("[apk]\n")
          writer.write("name = " + fileUri + "\n")
          writer.write("so_files = " + so_files.mkString(",") + "\n")
          writer.write("native_activities = " + native_acts.mkString(",") + "\n")
          writer.write("native_methods = " + native_methods.mkString(",") + "\n")
          writer.write("exec = " + execs + "\n")
          writer.close()
        } catch {
          case e: Exception =>
            throw e
        } finally {
          writer.close()
        }
      } catch {
        case e: Exception =>
          e.printStackTrace()
      } finally {
        if(outApkUri != null) {
          ConverterUtil.cleanDir(outApkUri)
          FileUtil.toFile(outApkUri).delete()
        }
      }
    }
  }

  def apply(reportsPath: String): Unit = {
    var total: Int = 0
    var so: Int = 0
    var nm: Int = 0
    var na: Int = 0
    var ex: Int = 0
    var nm_passdata: Int = 0
    var nm_passobject: Int = 0
    val sofiles: MSet[String] = msetEmpty
    val passObjects: MSet[JawaType] = msetEmpty

    FileUtil.listFiles(reportsPath, ".ini", recursive = true).foreach { iniUri =>
      val ini = new Wini(FileUtil.toFile(iniUri))
      val name: String = ini.get("apk", "name", classOf[String])
      val so_files: ISet[FileResourceUri] = ini.get("apk", "so_files", classOf[FileResourceUri]).split(",").toSet.filter(_.nonEmpty)
      val native_acts: ISet[JawaType] = ini.get("apk", "native_activities", classOf[String]).split(",").toSet.filter(_.nonEmpty).map(new JawaType(_))
      val native_methods: ISet[Signature] = ini.get("apk", "native_methods", classOf[String]).split(",").toSet.filter(_.nonEmpty).map(new Signature(_))
      val execs: Int = ini.get("apk", "exec", classOf[Int])
    }
  }
}
