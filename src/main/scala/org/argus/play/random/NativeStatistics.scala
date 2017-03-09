package org.argus.play.random

import java.io.{File, FileWriter}

import org.apache.commons.lang3.StringUtils
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.dedex.PilarStyleCodeGeneratorListener
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.jawa.core.util.{MyFileUtil, MyTimeout}
import org.argus.jawa.core._
import org.argus.play.cli.util.CliLogger
import org.argus.play.util.Utils
import org.ini4j.Wini
import org.sireum.util._

import scala.concurrent.duration._


/**
  * Generate the statistics of native lib usage from given dataset.
  */
object NativeStatistics {

  class DecompileTimer(time: FiniteDuration) extends PilarStyleCodeGeneratorListener {
    val timer = new MyTimeout(time)
    override def onRecordGenerated(recType: JawaType, code: String, outputUri: Option[FileResourceUri]): Unit = {
      timer.isTimeoutThrow()
    }

    override def onGenerateEnd(recordCount: Int): Unit = {}
  }

  def apply(sourcePath: String, outputPath: String): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      i += 1
      println(i + " of " + decs.size + ":####" + fileUri + "####")
      if(Apk.isDecompilable(fileUri)) {
        var outApkUri: FileResourceUri = ApkFileUtil.getOutputUri(fileUri, outputUri)
        try {
          /******************* Load given Apk *********************/
          val reporter = new DefaultReporter
          // Global is the class loader and class path manager
          val global = new Global(fileUri, reporter)
          global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
          val layout = DecompileLayout(outputUri)
          val settings = DecompilerSettings(
            AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri),
            dexLog = false, debugMode = false, removeSupportGen = true,
            forceDelete = false, Some(new DecompileTimer(5 minutes)), layout)
          val apk = Utils.loadApk(fileUri, settings, global)
          outApkUri = apk.outApkUri

          /******************* Get all .so files *********************/
          val so_files = FileUtil.listFiles(apk.outApkUri, ".so", recursive = true)

          /******************* Get all native methods and Runtime.exec *********************/
          val native_methods: MSet[Signature] = msetEmpty
          var execs = 0
          global.getApplicationClassCodes foreach { case (typ, sf) =>
            val mc = global.getMyClass(typ).get
            native_methods ++= mc.methods.filter(m => AccessFlag.isNative(m.accessFlag)).map(_.signature)
            execs += StringUtils.countMatches(sf.code, "`java.lang.Runtime.exec`")
          }

          /******************* Get NativeActivities *********************/
          val native_acts = apk.getComponentInfos.map(_.compType).filter { a =>
            global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(a, new JawaType("android.app.NativeActivity"))
          }

          /******************* Write report *********************/
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

  def apply(reportsPath: String): Unit = {
    val reportsUri = FileUtil.toUri(reportsPath)
    var total: Int = 0
    var haveNative: Int = 0
    var haveSo: Int = 0
    var haveNativeMethod: Int = 0
    var haveNativeActivity: Int = 0
    var haveExec: Int = 0
    var nativeMethod_total: Int = 0
    var nativeMethod_passdata: Int = 0
    var nativeMethod_object: Int = 0
    val sofiles: MSet[String] = msetEmpty
    val passObjects: MSet[JawaType] = msetEmpty
    val nativeMethods: MSet[Int] = msetEmpty
    try {

      FileUtil.listFiles(reportsUri, ".ini", recursive = true).foreach { iniUri =>
        total += 1
        val ini = new Wini(FileUtil.toFile(iniUri))
//        val name: String = ini.get("apk", "name", classOf[String])
        val so_files: ISet[FileResourceUri] = ini.get("apk", "so_files", classOf[FileResourceUri]).split(",").toSet.filter(_.nonEmpty)
        val native_acts: ISet[JawaType] = ini.get("apk", "native_activities", classOf[String]).split(",").toSet.filter(_.nonEmpty).map(new JawaType(_))
        val native_methods: ISet[Signature] = ini.get("apk", "native_methods", classOf[String]).split(",").toSet.filter(_.nonEmpty).map(new Signature(_))
        val execs: Int = ini.get("apk", "exec", classOf[Int])

        if (so_files.nonEmpty || native_acts.nonEmpty || native_methods.nonEmpty) haveNative += 1
        if (so_files.nonEmpty) haveSo += 1
        if (native_methods.nonEmpty) haveNativeMethod += 1
        nativeMethods += native_methods.size
        nativeMethod_total += native_methods.size
        nativeMethod_passdata += native_methods.count(_.getParameterNum != 0)
        nativeMethod_object += native_methods.count(_.getObjectParameters.nonEmpty)
        if (native_acts.nonEmpty) haveNativeActivity += 1
        if (execs != 0) haveExec += 1
        sofiles ++= so_files.map(FileUtil.toFile(_).getName)
        native_methods.foreach { method =>
          passObjects ++= method.getObjectParameters.values
        }
      }
    } catch {
      case e: Exception => e.printStackTrace()
    }

    val haveNative_per = haveNative.toFloat / total
    val haveNativeMethod_per = haveNativeMethod.toFloat / haveNative
    val haveSo_per = haveSo.toFloat / haveNative
    val haveNativeActivity_per = haveNativeActivity.toFloat / haveNative
    val haveExec_per = haveExec.toFloat / haveNative
    val nm_passdata_per = nativeMethod_passdata.toFloat / nativeMethod_total
    val nm_object_per = nativeMethod_object.toFloat / nativeMethod_total
    val avg_nm = average(nativeMethods)

    println("haveNative_per: " + haveNative_per + "\nhaveNativeMethod_per: " + haveNativeMethod_per + "\nhaveSo_per: " + haveSo_per + "\nhaveNativeActivity_per: " + haveNativeActivity_per + "\nhaveExec_per: " + haveExec_per + "\nnm_passdata_per: " + nm_passdata_per + "\nnm_object_per: " + nm_object_per + "\navg_nm: " + avg_nm)
    println()
    println("so_files: \n" + sofiles.mkString("\n"))
    println()
    println("nm_objects: \n" + passObjects.mkString("\n"))
  }

  def average[T]( ts: Iterable[T] )( implicit num: Numeric[T] ): Double = {
    num.toDouble( ts.sum ) / ts.size
  }
}
