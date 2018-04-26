package org.argus.play.random

import java.io.{File, FileWriter}

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.model.Intent
import org.argus.amandroid.summary.wu.IntentWu
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTASlot
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core.{DefaultReporter, Global, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jawa.summary.wu.{PTStore, PTSummary, WorkUnit}
import org.argus.play.cli.util.CliLogger

/**
  * Resolve all intent in the app.
  */
object IntentResolver  {
  def apply(sourcePath: String, outputPath: String, startNum: Int, endNum: Int): Unit = {
    val pathUri = FileUtil.toUri(sourcePath)
    val outputUri = FileUtil.toUri(outputPath)

    /******************* Get all Apks *********************/
    val decs = FileUtil.listFiles(pathUri, ".apk", recursive = true)
    var i = 0
    decs foreach { fileUri =>
      val fileName = FileUtil.toFile(fileUri).getName
      i += 1
      if(i >= startNum && i < endNum) {
        println(i + " of " + decs.size + ":####" + fileUri + "####")
        var outApkUri: FileResourceUri = null
        try {
          /** ***************** Load given Apk *********************/
          val reporter = new DefaultReporter
          val yard = new ApkYard(reporter)
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout)
          val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
          val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)
          outApkUri = apk.model.layout.outputSrcUri

          /** ***************** Resolve Intent **********************/
          val handler: AndroidModelCallHandler = new AndroidModelCallHandler
          val sm: SummaryManager = new AndroidSummaryProvider(apk).getSummaryManager
          val analysis = new BottomUpSummaryGenerator[Global](apk, sm, handler,
            PTSummary(_, _),
            ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
          val store: PTStore = new PTStore

          val sigs: ISet[Signature] = apk.model.getComponentInfos.flatMap(apk.getEntryPoints)
          val cg = SignatureBasedCallGraph(apk, sigs, None)
          val orderedWUs: IList[WorkUnit[Global]] = cg.topologicalSort(true).map { sig =>
            val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
            new IntentWu(apk, method, sm, handler, store, "intent")
          }
          analysis.build(orderedWUs)
          val candidate = store.getPropertyOrElse[MSet[(Context, PTASlot)]]("intent", msetEmpty)
          val intents: MSet[Intent] = msetEmpty
          candidate.foreach { case (ctx, s) =>
            val intentInss = store.resolved.pointsToSet(ctx, s)
            intents ++= IntentHelper.getIntentContents(store.resolved, intentInss, ctx)
          }

          /** ***************** Write report *********************/
          val report_fileuri = FileUtil.appendFileName(outputUri, "report.txt")
          val writer = new FileWriter(FileUtil.toFile(report_fileuri), true)
          try {
            writer.write(fileName + " total_intent: " + intents.size + " precise: " + intents.count(_.precise) + "\n")
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
