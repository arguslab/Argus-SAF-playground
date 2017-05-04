package org.argus.play.tutorial

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidRFAConfig, AndroidReachingFactsAnalysis}
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.dataDependenceAnalysis.InterProceduralDataDependenceAnalysis
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFactFactory
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.{ClassLoadManager, DefaultLibraryAPISummary, DefaultReporter}

/**
  * Created by fgwei on 2/22/17.
  */
class TaintAnalysis {
  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri(args(0))
    val outputUri = FileUtil.toUri(args(1))
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(new DefaultLibraryAPISummary(AndroidGlobalConfig.settings.third_party_lib_file), layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)

    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(fileUri, settings, collectInfo = true)

    val component = apk.model.getComponents.head // get any component you want to perform analysis
    apk.model.getEnvMap.get(component) match {
      case Some((esig, _)) =>
        val ep = apk.getMethod(esig).get
        implicit val factory = new RFAFactFactory
        val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(ep)
        val idfg = AndroidReachingFactsAnalysis(apk, ep, initialfacts, new ClassLoadManager, new Context(apk.nameUri), timeout = None)
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
        val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)
      case None =>
        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
    }
  }
}
