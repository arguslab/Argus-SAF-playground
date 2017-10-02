package org.argus.play.tutorial

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util.FileUtil

/**
  * Created by fgwei on 2/22/17.
  */
class LoadApk {
  def main(args: Array[String]): Unit = {
    if(args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri(args(0))
    val outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)

    val appName = apk.model.getAppName
    val certificate = apk.model.getCertificates
    val uses_permissions = apk.model.getUsesPermissions
    val component_infos = apk.model.getComponentInfos // ComponentInfo(compType: [class type], typ: [ACTIVITY, SERVICE, RECEIVER, PROVIDER], exported: Boolean, enabled: Boolean, permission: ISet[String])
    val intent_filter = apk.model.getIntentFilterDB // IntentFilterDB contains intent filter information for each component.
    val environment_map = apk.model.getEnvMap // environment method map
  }
}
