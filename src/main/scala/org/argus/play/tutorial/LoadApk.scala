package org.argus.play.tutorial

import java.io.File

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.argus.jawa.core.{Constants, DefaultReporter, Global}
import org.sireum.util.{FileResourceUri, FileUtil, ISet}

/**
  * Created by fgwei on 2/22/17.
  */
class LoadApk {
  def loadCode(apkUri: FileResourceUri, settings: DecompilerSettings, global: Global): (FileResourceUri, ISet[String]) = {
    val (outUri, srcs, _) = ApkDecompiler.decompile(apkUri, settings)
    srcs foreach {
      src =>
        val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
        if(FileUtil.toFile(fileUri).exists()) {
          //store the app's jawa code in global which is organized class by class.
          global.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
        }
    }
    (outUri, srcs)
  }

  def loadApk(apkUri: FileResourceUri, settings: DecompilerSettings, global: Global): Apk = {
    val (outUri, srcs) = loadCode(apkUri, settings, global)
    val apk = new Apk(apkUri, outUri, srcs)
    AppInfoCollector.collectInfo(apk, global, outUri)
    apk
  }

  def main(args: Array[String]): Unit = {
    if(args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri(args(0))
    val outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    // Global is the class loader and class path manager
    val global = new Global(fileUri, reporter)
    global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
    val layout = DecompileLayout(outputUri)
    val settings = DecompilerSettings(
      AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri),
      dexLog = false, debugMode = false, removeSupportGen = true,
      forceDelete = false, None, layout)
    val apk = loadApk(fileUri, settings, global)

    val appName = apk.getAppName
    val certificate = apk.getCertificates
    val uses_permissions = apk.getUsesPermissions
    val component_infos = apk.getComponentInfos // ComponentInfo(compType: [class type], typ: [ACTIVITY, SERVICE, RECEIVER, PROVIDER], exported: Boolean, enabled: Boolean, permission: ISet[String])
    val intent_filter = apk.getIntentFilterDB // IntentFilterDB contains intent filter information for each component.
    val environment_map = apk.getEnvMap // environment method map
  }
}
