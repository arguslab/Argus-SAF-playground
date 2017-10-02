package org.argus.play.random

import java.io.FileWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.decompile._
import org.argus.amandroid.core.parser.ComponentType
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.play.cli.util.CliLogger
import org.ini4j.Wini

/**
  * Generate the statistics of native lib usage from given dataset.
  */
object NativeStatistics {

  def apply(sourcePath: String, outputPath: String, startNum: Int, endNum: Int, timeout: Int): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      i += 1
      if(i >= startNum && i < endNum) {
        println(i + " of " + decs.size + ":####" + fileUri + "####")
        if (ApkGlobal.isDecompilable(fileUri)) {
          collectNative(i, fileUri, outputUri)
        }
      }
    }
  }

  private def collectNative(i: Int, fileUri: FileResourceUri, outputUri: FileResourceUri): Unit = {
    var outApkUri: FileResourceUri = null
    try {
      /******************* Load given Apk *********************/
      println("Start Loading Apk!")
      val reporter = new PrintReporter(MsgLevel.NO)
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout, sourceLevel = DecompileLevel.SIGNATURE, thirdPartyLibLevel = DecompileLevel.NO)
      val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
      val yard = new ApkYard(reporter)
      val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
      outApkUri = apk.model.layout.outputSrcUri
      println("Apk Loaded!")

      /******************* Get all .so files *********************/
      println("Get all so.")
      val so_files = FileUtil.listFiles(outApkUri, ".so", recursive = true)

      /******************* Get all native methods *********************/
      println("Get all native methods.")
      val native_methods: MSet[Signature] = msetEmpty
//      var execs = 0
      apk.getApplicationClassCodes foreach { case (typ, _) =>
        apk.getMyClass(typ) match {
          case Some(mc) =>
            native_methods ++= mc.methods.filter (m => AccessFlag.isNative (m.accessFlag) ).map (_.signature)
          case None =>
        }
      }

      /******************* Get NativeActivities *********************/
      println("Get NativeActivities.")
      val nativeActivity = apk.getClassOrResolve(new JawaType("android.app.NativeActivity"))
      val manifestUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "AndroidManifest.xml")
      val mfp = AppInfoCollector.analyzeManifest(apk.reporter, manifestUri)

      val native_acts = mfp.getComponentInfos.filter(_.typ == ComponentType.ACTIVITY).map(_.compType).filter { a =>
        val act = apk.getClassOrResolve(a)
        nativeActivity.isAssignableFrom(act)
      }

      /******************* Write report *********************/
      println("Writing Report.")
      val report_fileuri = FileUtil.appendFileName(outputUri, "report" + i + ".ini")
      val writer = new FileWriter(FileUtil.toFile(report_fileuri), false)
      try {
        writer.write("[apk]\n")
        writer.write("name = " + fileUri + "\n")
        writer.write("so_files = " + so_files.mkString(",") + "\n")
        writer.write("native_activities = " + native_acts.mkString(",") + "\n")
        writer.write("native_methods = " + native_methods.mkString(",") + "\n")
//        writer.write("exec = " + execs + "\n")
        writer.close()
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

  def apply(reportsPath: String): Unit = {
    val reportsUri = FileUtil.toUri(reportsPath)
    var total: Int = 0
    var haveNative: Int = 0
    var haveSo: Int = 0
    var haveNativeMethod: Int = 0
    var haveNativeActivity: Int = 0
//    var haveExec: Int = 0
    var nativeMethod_total: Int = 0
    var nativeMethod_passdata: Int = 0
    var nativeMethod_object: Int = 0
    val sofiles: MSet[String] = msetEmpty
    val archis: MMap[String, Int] = mmapEmpty
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
//        val execs: Int = ini.get("apk", "exec", classOf[Int])

        if (so_files.nonEmpty || native_acts.nonEmpty || native_methods.nonEmpty) haveNative += 1
        if (so_files.nonEmpty) haveSo += 1
        if (native_methods.nonEmpty) haveNativeMethod += 1
        nativeMethods += native_methods.size
        nativeMethod_total += native_methods.size
        nativeMethod_passdata += native_methods.count(_.getParameterNum != 0)
        nativeMethod_object += native_methods.count(_.getObjectParameters.nonEmpty)
        if (native_acts.nonEmpty) haveNativeActivity += 1
//        if (execs != 0) haveExec += 1
        so_files.foreach{ file =>
          val f = FileUtil.toFile(file)
          sofiles += f.getName
          val i = archis.getOrElseUpdate(f.getParentFile.getName, 0) + 1
          archis.put(f.getParentFile.getName, i)
        }
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
//    val haveExec_per = haveExec.toFloat / haveNative
    val nm_passdata_per = nativeMethod_passdata.toFloat / nativeMethod_total
    val nm_object_per = nativeMethod_object.toFloat / nativeMethod_total
    val avg_nm = average(nativeMethods)

    println("total: " + total + "\nhaveNative: " + haveNative + "\nhaveSo: " + haveSo + "\nhaveNativeMethod: " + haveNativeMethod + "\nhaveNativeActivity: " + haveNativeActivity + "\nnativeMethod_total: " + nativeMethod_total + "\nnativeMethod_passdata: " + nativeMethod_passdata + "\nnativeMethod_object: " + nativeMethod_object)
    println()
    println("haveNative_per: " + haveNative_per + "\nhaveNativeMethod_per: " + haveNativeMethod_per + "\nhaveSo_per: " + haveSo_per + "\nhaveNativeActivity_per: " + haveNativeActivity_per + "\nnm_passdata_per: " + nm_passdata_per + "\nnm_object_per: " + nm_object_per + "\navg_nm: " + avg_nm)
    println()
    println("architectures: \n" + archis.map{case (k, v) => k + ":" + v}.mkString("\n"))
    println()
    println("so_files: \n" + sofiles.mkString("\n"))
    println()
    println("nm_objects: \n" + passObjects.mkString("\n"))
  }

  def average[T]( ts: Iterable[T] )( implicit num: Numeric[T] ): Double = {
    num.toDouble( ts.sum ) / ts.size
  }
}
