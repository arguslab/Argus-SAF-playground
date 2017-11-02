package org.argus.play.random

import java.io.PrintWriter

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
import org.argus.jawa.alir.pta.rfa.SimHeap
import org.argus.jawa.alir.pta.{Instance, PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
public String getInnerSDCard()
        {
          return Environment.getExternalStorageDirectory().getPath();
        }
public String getInnerSDCard2()
        {
          return Environment.getExternalStorageDirectory().getPath();
        }
        String name2 = "/ztsecondfile";
    		File saveFile2=new File(name2);
            FileOutputStream outputStream2 =new FileOutputStream(saveFile2);
            outputStream2.write(content.getBytes());
            outputStream2.flush();
            outputStream2.close();

    		File saveFile=new File(getInnerSDCard()+"ztfirstfile.txt");
            FileOutputStream outputStream =new FileOutputStream(saveFile);
            outputStream.write(content.getBytes());
            outputStream.flush();
            outputStream.close();

  File saveFile4=new File(getInnerSDCard2()+"ztfirstfile.txt");
            FileOutputStream outputStream4 =new FileOutputStream(saveFile);
            outputStream4.write(content.getBytes());
            outputStream4.flush();
            outputStream4.close();



  Created by Tong Zhu
  */
object FileResolver {
  def main(args: Array[String]): Unit = {
    val fileUri = FileUtil.toUri(args(0))
    val outputUri = FileUtil.toUri(args(1))
    /******************* Load APK *********************/

    val reporter = new DefaultReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)

    /******************* Do Taint analysis *********************/

    val component = apk.model.getComponents.last // get any component you want to perform analysis
    apk.model.getEnvMap.get(component) match {
      case Some((esig, _)) =>
        val ep = apk.getMethod(esig).get
        implicit val heap: SimHeap = new SimHeap
        val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
        val icfg = new InterProceduralControlFlowGraph[ICFGNode]
        val ptaresult = new PTAResult
        val sp = new AndroidSummaryProvider(apk)
        val analysis = new AndroidReachingFactsAnalysis(
          apk, icfg, ptaresult, AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
          AndroidReachingFactsAnalysisConfig.resolve_static_init,
          timeout = None)
        val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
        idfg.ptaresult.pprint()
        idfg.icfg.toDot(new PrintWriter(System.out))
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
        val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)

        /******************* Resolve all URL value *********************/
        val urlMap: MMap[Context, MSet[Any]] = mmapEmpty
        val urlMap2: MMap[Context, Context] = mmapEmpty
        val urlMap3: MMap[Context, MSet[Any]] = mmapEmpty
        var test3 : MSet[Any] = msetEmpty
        val urlMap5: MMap[Context, MSet[Any]] = mmapEmpty
        val urlMap4: MMap[Context, Context] = mmapEmpty
        val urlMap6: MMap[Context, MSet[String]] = mmapEmpty
        val urlMap7: MMap[Context, Context] = mmapEmpty
        val urlMap8: MMap[Context, Context] = mmapEmpty
        val urlMap9: MMap[Any, Any] = mmapEmpty
        val urlMap9plus: MMap[Context, MSet[Any]] = mmapEmpty
        val urlMap10: MMap[Context, Context] = mmapEmpty
        val urlMap11: MMap[Context, Context] = mmapEmpty
        val urlMap15: MMap[Context, MSet[Any]] = mmapEmpty
        val urlMap16: MMap[Context, MSet[Any]] = mmapEmpty
        idfg.icfg.nodes foreach {
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/io/File;.<init>:(Ljava/lang/String;)V")|cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.<init>:(Ljava/lang/String;)V") =>
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            val strSlot = VarSlot(cn.argNames(1))
            val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext, strSlot)
            for(url <- urls;
                urlvalue <- urlvalues) {
              urlMap4.getOrElseUpdate(urlvalue.defSite, url.defSite)
            }
            val urlvalues2 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot) map {
              case pcsi: PTAConcreteStringInstance => pcsi.string
              case pcsi: Instance => pcsi.defSite
              case _ => "ANY"
            }
            for(url <- urls;
                urlvalue <- urlvalues2) {
              urlMap.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
            }

          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/lang/StringBuilder;.<init>:(Ljava/lang/String;)V") => //Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
            var test4 : Set[Context] = Set()
            test4 += cn.context
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            val strSlot = VarSlot(cn.argNames(1))
            val urlvalues3 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot)
            for(urlvalue <- test4;
                url <- urls) {
              urlMap10.getOrElseUpdate(urlvalue,url.defSite)
            }
            for(urlvalue <- test4;
                url <- urlvalues3) {
              urlMap11.getOrElseUpdate(urlvalue,url.defSite)
            }
            val urlvalues4 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot) map {
              case pcsi: PTAConcreteStringInstance => pcsi.string
              case pcsi: Instance => pcsi.defSite
              case _ => "ANY"
            }
            for(urlvalue <- urlvalues4;
                url <- urls) {
              urlMap5.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
            }
            for(urlvalue <- urlvalues4;
                url <- urls) {
              urlMap15.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
            }
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/lang/StringBuilder;.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;") => //Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
            var test4 : Set[Context] = Set()
            test4 += cn.context
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            val strSlot = VarSlot(cn.argNames(1))
            val urlvalues3 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot)
            for(urlvalue <- test4;
                url <- urls) {
              urlMap10.getOrElseUpdate(urlvalue,url.defSite)
            }
            val urlvalues4 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot) map {
              case pcsi: PTAConcreteStringInstance => pcsi.string
              case pcsi: Instance => pcsi.defSite
              case _ => "ANY"
            }
            for(urlvalue <- urlvalues4;
                url <- urls) {
              urlMap5.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
              urlMap16.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
            }
            for(urlvalue <- urlvalues4;
                url <- test4) {
              urlMap16.getOrElseUpdate(url , msetEmpty) += urlvalue
            }
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/os/Environment;.getExternalStorageDirectory:()Ljava/io/File;") =>
            test3 += cn.context
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/io/File;.getPath:()Ljava/lang/String;") => //Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
            var test : Set[Context] = Set()
            test += cn.context
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            for(urlvalue <- test;
                url <- urls) {
              urlMap8.getOrElseUpdate(urlvalue, url.defSite)
            }
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;") => //Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;
            var test2 : Set[Context] = Set()
            test2 += cn.context
            val urlSlot = VarSlot(cn.argNames.head)
            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
            for(urlvalue <- test2;
                url <- urls) {
              urlMap7.getOrElseUpdate(urlvalue, url.defSite)
            }
          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V")|cn.getCalleeSig == new Signature("Ljava/io/BufferedWriter;.<init>:(Ljava/io/Writer;)V") =>
            val urlSlot2 = VarSlot(cn.argNames.head)
            val urls2 = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot2)
            val strSlot2 = VarSlot(cn.argNames(1))
            val urlvalues2 = idfg.ptaresult.pointsToSet(cn.getContext, strSlot2)
            for(urlvalue <- urlvalues2;
                url <- urls2) {
              urlMap2.getOrElseUpdate(urlvalue.defSite, url.defSite)
            }
          case _ =>
        }
        /*******************************************/
        urlMap2.keys.foreach{
          i=>
            urlMap.keys.foreach{
              j=>
                if (i ==j){
                  urlMap3.getOrElseUpdate(urlMap2(i), urlMap(j))
                }
            }
        }
        urlMap7.keys.foreach{//change valveOf to environment by .path()
          i=>
            urlMap8.keys.foreach{
              j=>
                if (urlMap7(i) ==j){
                  urlMap9plus.getOrElseUpdate(i,msetEmpty ) +=urlMap8(j)
                }
            }
        }
        urlMap9plus.keys.foreach{//exchange valueOf with environment
          i=>
            urlMap5.keys.foreach{
              j=>
                if (urlMap5(j).contains(i)){
                  urlMap5(j) -= i
                  urlMap5(j) += urlMap9plus(i)
                }
            }
        }
        urlMap9plus.keys.foreach {//change environment to "SDCard"
          i =>
            test3.foreach{
              j=>
                if (urlMap9plus(i).contains(j)){
                  urlMap9plus(i) -= j
                  urlMap9plus(i) += "SDCard"
                }
            }

        }

        urlMap.keys.foreach{//exchange valueOf with environment
          i=>
            urlMap16.keys.foreach{
              j=>
                if (urlMap(i).contains(j)){
                  urlMap(i) -= j
                  urlMap(i) += urlMap16(j)
                }
            }
        }
        urlMap.keys.foreach{
          i=>
            urlMap9plus.keys.foreach{
              j=>
                if (urlMap(i).contains(j)){
                  urlMap(i) -= j
                  urlMap(i) += urlMap9plus(j)
                }
            }
        }

        /******************* Retrieve URL value *********************/

        val gisNodes = taint_analysis_result.getSinkNodes.filter{
          node =>
            node.node.node match {
              case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileOutputStream;.write:([B)V") =>
                true
              case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V") =>
                true
              case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V") =>
                true
              case _ => false
            }
        }
        println("*****************************************************")
        gisNodes.foreach {
          gisnode =>

            if (gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/FileOutputStream;.write:([B)V")|gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V")){
              val invNode = gisnode.node.node.asInstanceOf[ICFGInvokeNode]
              val connSlot = VarSlot(invNode.argNames.head)
              val connValues = idfg.ptaresult.pointsToSet(invNode.getContext, connSlot)

              connValues foreach {
                urlValue =>
                  println("URL value at " + gisnode.descriptor + "@" + gisnode.node.node.getContext.getLocUri + "\nis:\n" + urlMap3.getOrElse(urlValue.defSite, msetEmpty).mkString("\n"))
              }
            }
            if (gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V")){
              val invNode = gisnode.node.node.asInstanceOf[ICFGInvokeNode]
              val connSlot = VarSlot(invNode.argNames.head)
              val connValues = idfg.ptaresult.pointsToSet(invNode.getContext, connSlot)

              connValues foreach {
                urlValue =>
                  println("URL value at " + gisnode.descriptor + "@" + gisnode.node.node.getContext.getLocUri + "\nis:\n" + urlMap.getOrElse(urlValue.defSite, msetEmpty).mkString("\n"))
              }
            }
        }
        println("Done!" +"\n"+ "*****************************************************")
      case None =>
        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
    }
  }
}
