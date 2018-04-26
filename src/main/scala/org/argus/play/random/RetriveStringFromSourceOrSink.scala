package org.argus.play.random

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.{ICFGCallNode, ICFGInvokeNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dda.InterProceduralDataDependenceAnalysis
import org.argus.jawa.alir.pta.{PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
  * Retrieve URL from connectionInputStream.
  *
  * Code:
  *
  * private void get() {
  *     try {
  *         URL url = new URL("http://www.arguslab.org/");
  *         URLConnection urlConnection = url.openConnection();
  *         BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
  *         String line = in.readLine();
  *         Log.d("data", line);
  *     } catch (IOException e) {
  *         e.printStackTrace();
  *     }
  * }
  *
  * Created by fgwei on 2/22/17.
  */
object RetriveStringFromSourceOrSink {

  def main(args: Array[String]): Unit = {
    val fileUri = FileUtil.toUri(getClass.getResource("/random/ReadInternet.apk").getPath)
    val outputUri = FileUtil.toUri(getClass.getResource("/output").getPath)

    /******************* Load APK *********************/

    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)

    /******************* Do Taint analysis *********************/

    val component = apk.model.getComponents.head // get any component you want to perform analysis
    apk.model.getEnvMap.get(component) match {
      case Some((esig, _)) =>
        val ep = apk.getMethod(esig).get
        val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
        val icfg = new InterProceduralControlFlowGraph[ICFGNode]
        val ptaresult = new PTAResult
        val sp = new AndroidSummaryProvider(apk)
        val analysis = new AndroidReachingFactsAnalysis(
          apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
          AndroidReachingFactsAnalysisConfig.resolve_static_init,
          timeout = None)
        val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
        val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)

        /******************* Resolve all URL value *********************/

        val urlMap: MMap[Context, MSet[String]] = mmapEmpty
        idfg.icfg.nodes foreach {
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/net/URL;.<init>:(Ljava/lang/String;)V") =>
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            val strSlot = VarSlot(cn.argNames(1))
            val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext, strSlot) map {
              case pcsi: PTAConcreteStringInstance => pcsi.string
              case _ => "ANY"
            }
            for(url <- urls;
                urlvalue <- urlvalues) {
              urlMap.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
            }
          case _ =>
        }

        /******************* Retrieve URL value *********************/

        val gisNodes = taint_analysis_result.getSourceNodes.filter{ node =>
          node.node.node match {
            case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/net/URLConnection;.getInputStream:()Ljava/io/InputStream;") =>
              true
            case _ => false
          }
        }
        gisNodes.foreach {
          node =>
            val invNode = node.node.node.asInstanceOf[ICFGInvokeNode]
            val connSlot = VarSlot(invNode.argNames.head)
            val connValues = idfg.ptaresult.pointsToSet(invNode.getContext, connSlot)
            connValues foreach {
              connValue =>
                val urlInvNode = idfg.icfg.getICFGCallNode(connValue.defSite).asInstanceOf[ICFGCallNode]
                val urlSlot = VarSlot(urlInvNode.argNames.head)
                val urlValues = idfg.ptaresult.pointsToSet(connValue.defSite, urlSlot)
                urlValues foreach { urlValue =>
                  println("URL value at " + node.descriptor + "@" + node.node.node.getContext.getLocUri + "\nis:\n" + urlMap.getOrElse(urlValue.defSite, msetEmpty).mkString("\n"))
                }
            }
        }
      case None =>
        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
    }
  }
}
