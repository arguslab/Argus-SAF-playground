package org.argus.play.random

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.alir.pta.suspark.InterProceduralSuperSpark
import org.argus.jawa.core.{DefaultLibraryAPISummary, DefaultReporter}
import org.argus.jawa.core.util.FileUtil

object BuildSuperSpark {
  def main(args: Array[String]): Unit = {

    AndroidReachingFactsAnalysisConfig.parallel = false
    AndroidReachingFactsAnalysisConfig.resolve_static_init = true

    val inputUri = FileUtil.toUri("/Users/fgwei/Downloads/com.tencent.androidqqmail.apk")
    val outputUri = FileUtil.toUri("/Users/fgwei/Work/output")

    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val settings = DecompilerSettings(debugMode = false, forceDelete = false,
      reporter = reporter, listener = None,
      strategy = DecompileStrategy(layout, libraryAPISummary = new
          DefaultLibraryAPISummary(AndroidGlobalConfig.settings.third_party_lib_file)))
    val apk = yard.loadApk(inputUri, settings, collectInfo = true,
      resolveCallBack = false)

    apk.model.getComponents foreach { svc =>
      System.out.println(svc)
      val clz = apk.getClassOrResolve(svc)
      val eps = clz.getDeclaredMethods
      val spark = new InterProceduralSuperSpark(apk)
      val idfg = spark.build(eps.map(_.getSignature))
      System.out.println(idfg.ptaresult)
    }
  }
}
