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
import org.argus.jawa.alir.pta.{Instance, PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.core._
import org.argus.jawa.core.util.{ISortedMap, MSet, _}
import org.argus.jawa.alir.reachability
import org.argus.jawa.alir.reachability.ReachabilityAnalysis

import scala.collection.GenSet
/**
  *FileResolver is used to find the files which contain sensitive information and it also find flie's path and name.
  *FileResolver can resolve the files being created by
  * .getDefaultSharedPreferences(),.getSharedPreferences(" ",  ),new FileOutputStream(),new OutputStreamWriter(),new BufferedWriter(),new File()
  * and the database file
  * class a extends SQLiteOpenHelper {
    a(Context arg4) {
        super(arg4, "downloadsDB", null, 1);
    }
  * @author <a href="mailto:tong.zh@foxmail.com">Tong Zhu</a>
  */
object FileResolver {
  class ListNode(value : Context){
    val v = value
    var head : ListNode = null
    var child : ListNode = null
    def getHead(): Context ={
      if (head == null){
        null
      }else{
        head.v
      }
    }
    def getChild(): Context ={
      if (child == null){
        null
      }else{
        child.v
      }
    }
  }
  def main(args: Array[String]):  Unit = {
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
    val listNodeSet : MSet[ListNode] = msetEmpty
    val childNodeSet : MSet[ListNode] = msetEmpty
    val urlMapPlus: MMap[Context, MList[Any]] = mmapEmpty
    val urlMap2Plus: MMap[Context, MSet[Any]] = mmapEmpty
    var test3 : MSet[Any] = msetEmpty
    val IntersectSet : GenSet[Signature] = GenSet(new Signature("Ljava/io/Writer;.write:(Ljava/lang/String;)V"),
     new Signature("Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"),
      new Signature("Ljava/io/FileWriter;.<init>:(Ljava/lang/String;)V"),
      new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"),
      new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J"),
      new Signature("Ljava/io/File;.<init>:(Ljava/io/File;Ljava/lang/String;)V"),
      new Signature("Ljava/io/FileWriter;.<init>:(Ljava/io/File;Z)V"),
      new Signature("Landroid/os/Environment;.getExternalStorageDirectory:()Ljava/io/File;"),
      new Signature("Landroid/content/Context;.getPackageName:()Ljava/lang/String;"),
      new Signature("Ljava/util/Date;.<init>:()V"),
      new Signature("Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V"),
      new Signature("Landroid/content/Intent;.getStringExtra:(Ljava/lang/String;)Ljava/lang/String;"),
      new Signature("Landroid/content/SharedPreferences;.edit:()Landroid/content/SharedPreferences$Editor;"),
      new Signature("Ljava/io/FileOutputStream;.write:([B)V"),
      new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V"),
      new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V"),
      new Signature("Ljava/io/RandomAccessFile;.writeChar:(I)V"),
      new Signature("Ljava/io/DataOutputStream;.writeBytes:(Ljava/lang/String;)V"),
      new Signature("Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"),
      new Signature("Landroid/content/SharedPreferences$Editor;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;"),
      new Signature("Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;"),
      new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J"),
      new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"))
    var test6 : MSet[Any] = msetEmpty
    var test7 : MSet[Context] = msetEmpty
    var DB_Name : MSet[String] = msetEmpty
    val urlMap17: MMap[Any, MSet[Any]] = mmapEmpty
    val urlMap18: MMap[Context, Any] = mmapEmpty
    val urlMap19: MMap[Context, MSet[Any]] = mmapEmpty
    var context1: MSet[Any] = msetEmpty
    var urlMapModel: MMap[Any, String] = mmapEmpty
    val L: MList[Any] = mlistEmpty
    var IndexMap0: MMap[Any, Any] = mmapEmpty
    val IndexMap: MMap[Context, MSet[MMap[Any, Any]]] = mmapEmpty
    val IndexMap2: MMap[String, String] = mmapEmpty
    var IndexMapCopy: MMap[Context, MSet[MMap[Any, Any]]] = mmapEmpty
    val IndexMap3: MMap[Context, MSet[MMap[Any, Any]]] = mmapEmpty
    val urlMapPlus3: MMap[Context, MList[Any]] = mmapEmpty
    val YourForNum: Int = 5
    var compNum: Int = 0
    val realcompNnm = apk.model.getComponents.size
    apk.model.getComponents.foreach{
      iComponents =>
        compNum += 1
        var mmapp:IMap[JawaType, ISet[Signature]] = imapEmpty
        mmapp = reachability.ReachabilityAnalysis.getReachableMethodsBySBCG(apk ,Set(iComponents) )
        /**you can use following codes if you want it to run faster**/
        //mmapp.foreach{
          //case( keys , values) =>
            //if(values.intersect(IntersectSet).nonEmpty){
              apk.model.getEnvMap.get(iComponents) match {
                case Some((esig, _)) =>
                  /**you can use following codes if you think your codes may have some errors**/
                  //try {
                  val ep = apk.getMethod(esig).get
                  val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
                  val icfg = new InterProceduralControlFlowGraph[ICFGNode]
                  val ptaresult = new PTAResult
                  val sp = new AndroidSummaryProvider(apk)
                  //AndroidReachingFactsAnalysisConfig.resolve_static_init = true
                  val analysis = new AndroidReachingFactsAnalysis(
                    apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
                    AndroidReachingFactsAnalysisConfig.resolve_static_init,
                    timeout = None)
                  val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
                  //idfg.ptaresult.pprint()
                  //print("==========================================" + "\n")
                  //idfg.icfg.toDot(new PrintWriter(System.out))
                  //print( idfg.icfg.toString() + "\n")
                  val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
                  val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
                  val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)
                  /******************* Resolve and retrieve all file's name value *********************/
                  idfg.icfg.nodes foreach{
                    i =>
                      L += i.getContext.getLocUri
                  }
                  idfg.icfg.nodes foreach {
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/io/File;.<init>:(Ljava/lang/String;)V")
                      |cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.<init>:(Ljava/lang/String;)V")
                      |cn.getCalleeSig == new Signature("Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V")
                      |cn.getCalleeSig == new Signature("Ljava/io/OutputStreamWriter;.<init>:(Ljava/io/OutputStream;)V")
                      |cn.getCalleeSig == new Signature("Ljava/io/BufferedWriter;.<init>:(Ljava/io/Writer;)V") =>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      val strSlot = VarSlot(cn.argNames(1))
                      val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                      for(url <- urls;
                          urlvalue <- urlvalues) {
                        IndexMap0.getOrElseUpdate(urlvalue.defSite.getCurrentLocUri, urlvalue)
                        if(urlvalue.isInstanceOf[PTAConcreteStringInstance]){
                          val urlvaluestring = urlvalue.asInstanceOf[PTAConcreteStringInstance].string
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluestring
                        }else if (urlvalue.isInstanceOf[Instance])
                        {
                          val urlvaluedef = urlvalue.asInstanceOf[Instance].defSite
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluedef
                        }else{
                          val urlvalueelse = "ANY"
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvalueelse
                        }
                        IndexMap.getOrElseUpdate(url.defSite, msetEmpty) += IndexMap0
                        IndexMap0 = mmapEmpty
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;") =>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      test7 += cn.context
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteOpenHelper;.<init>:(Landroid/content/Context;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;I)V") =>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      val strSlot = VarSlot(cn.argNames(2))
                      val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                      for(urlvalue <- urlvalues){
                        val urlvaluestring = urlvalue.asInstanceOf[PTAConcreteStringInstance].string
                        DB_Name += urlvaluestring
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.execSQL:(Ljava/lang/String;)V") =>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      test7 += cn.context
                      val strSlot = VarSlot(cn.argNames(1))
                      val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                      for(urlvalue <- urlvalues){
                        val urlvaluestring = urlvalue.asInstanceOf[PTAConcreteStringInstance].string
                        if(urlvaluestring.split("[(]")(0).trim().split("[ ]")(0).trim().equalsIgnoreCase("create")){
                          val structure = urlvaluestring.split("[(]")(1).trim().split("[)]")(0).trim()
                          val TBName = urlvaluestring.split("[(]")(0).trim().split("[ ]").last.trim()
                          IndexMap2.getOrElseUpdate(TBName, structure)
                        }
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I")|cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J") =>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      test7 += cn.context
                      val strSlot = VarSlot(cn.argNames(1))
                      val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                      for(url <- test7;
                          urlvalue <- urlvalues) {
                        IndexMap0.getOrElseUpdate(urlvalue.defSite.getCurrentLocUri, urlvalue)
                        if(urlvalue.isInstanceOf[PTAConcreteStringInstance]){
                          val urlvaluestring = urlvalue.asInstanceOf[PTAConcreteStringInstance].string
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluestring
                        }else if (urlvalue.isInstanceOf[Instance])
                        {
                          val urlvaluedef = urlvalue.asInstanceOf[Instance].defSite
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluedef
                        }else{
                          val urlvalueelse = "ANY"
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvalueelse
                        }
                        IndexMap.getOrElseUpdate(url, msetEmpty) += IndexMap0
                        IndexMap0 = mmapEmpty
                      }
                      test7 = msetEmpty
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/io/File;.<init>:(Ljava/io/File;Ljava/lang/String;)V")
                      | cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.<init>:(Ljava/io/File;Z)V")=>
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      val strSlot = VarSlot(cn.argNames(1))
                      val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                      val strSlot2 = VarSlot(cn.argNames(2))
                      val urlvalues2 = idfg.ptaresult.pointsToSet(cn.getContext , strSlot2)
                      for(url <- urls;
                          urlvalue <- urlvalues ++ urlvalues2) {
                        IndexMap0.getOrElseUpdate(urlvalue.defSite.getCurrentLocUri, urlvalue)
                        if(urlvalue.isInstanceOf[PTAConcreteStringInstance]){
                          val urlvaluestring = urlvalue.asInstanceOf[PTAConcreteStringInstance].string
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluestring
                        }else if (urlvalue.isInstanceOf[Instance])
                        {
                          val urlvaluedef = urlvalue.asInstanceOf[Instance].defSite
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluedef
                        }else{
                          val urlvalueelse = "ANY"
                          IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvalueelse
                        }
                        IndexMap.getOrElseUpdate(url.defSite, msetEmpty) += IndexMap0
                        IndexMap0 = mmapEmpty
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/os/Environment;.getExternalStorageDirectory:()Ljava/io/File;") =>
                      test3 += cn.context
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/content/Context;.getPackageName:()Ljava/lang/String;") =>
                      var test5 : MSet[Any] = msetEmpty
                      test5 += cn.context
                      test5.foreach(
                        url =>
                          urlMapModel = urlMapModel ++ Map(url -> cn.getOwner.getClassType.getPackageName)
                      )
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/util/Date;.<init>:()V") =>
                      test6 += cn.context
                      val urlSlot = VarSlot(cn.argNames.head)
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                      urls.foreach(
                        url =>
                          test6 += url.defSite
                      )
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;") =>
                      val urlSlot = VarSlot(cn.argNames(1))
                      val urls = idfg.ptaresult.pointsToSet(cn.getContext,urlSlot) map {
                        case pcsi: PTAConcreteStringInstance => pcsi.string
                        case pcsi: Instance => pcsi.defSite
                        case _ => "ANY"
                      }
                      val strSlot = VarSlot(cn.argNames(2))
                      val urlvalues2 = idfg.ptaresult.pointsToSet(cn.getContext,strSlot) map {
                        case pcsi: PTAConcreteStringInstance => pcsi.string
                        case pcsi: Instance => pcsi.defSite
                        case _ => "ANY"
                      }
                      for(urlvalue <- urlvalues2;
                          url <- urls) {
                        urlMap17.getOrElseUpdate(url,msetEmpty) += urlvalue
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/content/Intent;.getStringExtra:(Ljava/lang/String;)Ljava/lang/String;") =>
                      var self : Set[Context] = Set()
                      self += cn.context
                      val strSlot = VarSlot(cn.argNames(1))
                      val urlvalues2 = idfg.ptaresult.pointsToSet(cn.getContext,strSlot) map {
                        case pcsi: PTAConcreteStringInstance => pcsi.string
                        case pcsi: Instance => pcsi.defSite
                        case _ => "ANY"
                      }
                      for(urlvalue <- urlvalues2;
                          url <- self) {
                        urlMap18.getOrElseUpdate(url,urlvalue)
                      }
                    case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences;.edit:()Landroid/content/SharedPreferences$Editor;") =>
                      var selfs : MSet[Context] = msetEmpty
                      selfs += cn.context
                      val urlSlot2 = VarSlot(cn.argNames.head)
                      val heads = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot2)
                      for(head <- heads;
                          self <- selfs) {
                        urlMap2Plus.getOrElseUpdate(self,msetEmpty) += head.defSite
                      }
                      selfs = msetEmpty
                    case _ =>
                  }
                  /***make a link in case that there are some functions like "Ljava/io/File;.<init>:(Ljava/io/File;Ljava/lang/String;)V"****/
                  IndexMap.keys.foreach{
                    IndxK0 =>
                      IndexMap.keys.foreach{
                        IndxK =>
                          IndexMap(IndxK).foreach{
                            IndxMapV =>
                              IndxMapV.keys.foreach{
                                i =>
                                  if(IndxK0 == IndxMapV(i)){
                                    var LN = new ListNode(IndxK0)
                                    LN.head = new ListNode(IndxK)
                                    listNodeSet += LN
                                    var LN2 = new ListNode(IndxK)
                                    LN2.child = new ListNode(IndxK0)
                                    listNodeSet += LN2
                                  }
                              }
                          }
                      }
                  }
                  listNodeSet.foreach{
                    l =>
                      listNodeSet.foreach{
                        j =>
                          if (l.head != null && l.head.v == j.v){
                            j.child = l
                          }else if(l.child != null && l.child.v == j.v){
                            j.head = l
                          }
                      }
                  }
                  listNodeSet.foreach {
                    l =>
                      var finalChild : ListNode = null
                      if(l.child != null){
                        finalChild = l.child
                        while(finalChild.child != null){
                          finalChild = finalChild.child
                        }
                      }else{
                        finalChild = l
                      }
                      childNodeSet += finalChild
                  }
                  childNodeSet.foreach{
                    l =>
                      var finalHead : ListNode = l
                      while(finalHead.head != null){
                        IndexMap.keys.foreach{
                          IdxMapK =>
                            if(IdxMapK == finalHead.v){
                              IndexMap.keys.foreach{
                                K =>
                                  if(K == finalHead.head.v){
                                    IndexMap(K).foreach{
                                      M =>
                                        if(M.head._2 == finalHead.v){
                                          IndexMap(K) -= M
                                          IndexMap(K) = IndexMap(K) ++ IndexMap(IdxMapK)
                                        }
                                    }
                                  }
                              }
                            }
                        }
                        finalHead = finalHead.head
                      }
                  }
                  /*******resolve the names of the files which are created using getSharedPreferences or getDefaultSharedPreferences****/
                  urlMap2Plus.keys.foreach{
                    M2K =>
                      urlMap2Plus(M2K).foreach{
                        M2 =>
                          idfg.icfg.nodes foreach {
                            case cn: ICFGCallNode if cn.getContext == M2 && cn.getCalleeSig.getSubSignature == "getSharedPreferences:(Ljava/lang/String;I)Landroid/content/SharedPreferences;"=>
                              val urlSlot = VarSlot(cn.argNames.head)
                              val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                              var self : MSet[Context] = msetEmpty
                              self += cn.context
                              val strSlot = VarSlot(cn.argNames(1))
                              val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                              for(urlvalue <- urlvalues) {
                                IndexMap0.getOrElseUpdate(urlvalue.defSite.getCurrentLocUri, urlvalue)
                                if(urlvalue.isInstanceOf[PTAConcreteStringInstance]){
                                  val a = iComponents.getPackageName
                                  val urlvaluestring = "data/data/" + a + "/" + urlvalue.asInstanceOf[PTAConcreteStringInstance].string + ".xml"
                                  IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluestring
                                }else if (urlvalue.isInstanceOf[Instance])
                                {
                                  val urlvaluedef = urlvalue.asInstanceOf[Instance].defSite
                                  IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvaluedef
                                }else{
                                  val urlvalueelse = "ANY"
                                  IndexMap0(urlvalue.defSite.getCurrentLocUri) = urlvalueelse
                                }
                                IndexMap.getOrElseUpdate(M2K, msetEmpty) += IndexMap0
                                IndexMap0 = mmapEmpty
                              }
                              self = msetEmpty
                            case cn: ICFGCallNode if cn.getContext == M2 && cn.getCalleeSig.getSubSignature == "getDefaultSharedPreferences:(Landroid/content/Context;)Landroid/content/SharedPreferences;"=>
                              var self : MSet[Context] = msetEmpty
                              self += cn.context
                              for(urlvalue <- self) {
                                IndexMap0.getOrElseUpdate(urlvalue.getCurrentLocUri, urlvalue)
                                val a = iComponents.getPackageName
                                val urlvaluestring = "data/data/" + a + ".xml"
                                IndexMap0(urlvalue.getCurrentLocUri) = urlvaluestring
                                IndexMap.getOrElseUpdate(M2K, msetEmpty) += IndexMap0
                                IndexMap0 = mmapEmpty
                              }
                              self = msetEmpty
                            case _ =>
                          }
                      }

                  }
                  /******************Modeling Map*************************/
                  test3.foreach{//change environment.getExternalStorageDirectory() to "sdcard/"
                    j=>
                      urlMapModel = urlMapModel ++ Map(j -> "sdcard/")
                  }
                  test6.foreach{
                    j=>
                      urlMapModel = urlMapModel ++ Map(j -> "DateTime ")
                  }
                  /*******************Link Map to make a cross component analysis****************************/
                  urlMap17.keys.foreach {
                    i =>
                      urlMap18.keys.foreach {
                        j =>
                          IndexMap.keys.foreach {
                            IndxMapK =>
                              IndexMap(IndxMapK).foreach {
                                m =>
                                  m.keys.foreach {
                                    k =>
                                      if (j == m(k)) {
                                        urlMap19.getOrElseUpdate(j, urlMap17(i))
                                      }
                                  }
                              }
                          }
                      }
                  }
                  urlMap19.keys.foreach{
                    i=>
                      IndexMap.keys.foreach{
                        IndxMapK =>
                          IndexMap(IndxMapK).foreach{
                            j =>
                              j.keys.foreach{
                                k =>
                                  if(j(k) == i){
                                    j(k)  = urlMap19(i)
                                  }
                              }
                          }
                      }
                  }
                  /******************Loop*************************/
                  for(i <- 1 to 5){//you can change the condition of jumping out of the cycle here
                    IndexMapCopy = IndexMap
                    context1 = msetEmpty
                    IndexMap.keys.foreach{
                      IndexMapK =>
                        IndexMap(IndexMapK).foreach{
                          IndexMapV =>
                            IndexMapV.keys.foreach{
                              j =>
                                context1 += IndexMapV(j)
                            }
                        }
                    }
                    context1.foreach{
                      con =>
                        idfg.icfg.nodes foreach {
                          case cn: ICFGCallNode if cn.getContext == con =>
                            val size = cn.argNames.size
                            if (size == 0){
                              var temp: Any = ""
                              urlMapModel.keys.foreach{
                                i =>
                                  if(i == con){
                                    temp = urlMapModel(i)
                                  }
                              }
                              IndexMap.keys.foreach{
                                IndexMapK =>
                                  IndexMap(IndexMapK).foreach{
                                    IndexMapV =>
                                      IndexMapV.keys.foreach{
                                        i =>
                                          if(IndexMapV(i) == con){
                                            IndexMapV(i) = temp
                                          }
                                      }
                                  }
                              }
                            }
                            if (size == 1){
                              var flag = true
                              var temp: Any = ""
                              urlMapModel.keys.foreach{
                                i =>
                                  if(i == con){
                                    temp = urlMapModel(i)
                                    IndexMap.keys.foreach{
                                      IndexMapK =>
                                        IndexMap(IndexMapK).foreach{
                                          IndexMapV =>
                                            IndexMapV.keys.foreach{
                                              i =>
                                                if(IndexMapV(i) == con){
                                                  IndexMapV(i) = temp
                                                  flag = false
                                                }
                                            }
                                        }
                                    }
                                  }
                              }
                              if (flag == true){
                                val urlSlot2 = VarSlot(cn.argNames.head)
                                val urls2 = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot2)
                                for(url <- urls2) {
                                  IndexMap.keys.foreach{
                                    IndexMapK =>
                                      IndexMap(IndexMapK).foreach{
                                        IndexMapV =>
                                          IndexMapV.keys.foreach{
                                            i =>
                                              if(IndexMapV(i) == con){
                                                if(url.isInstanceOf[PTAConcreteStringInstance]){
                                                  val urlvaluestring = url.asInstanceOf[PTAConcreteStringInstance].string
                                                  val loc = url.asInstanceOf[PTAConcreteStringInstance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluestring)
                                                  IndexMap(IndexMapK) += map
                                                }else if (url.isInstanceOf[Instance])
                                                {
                                                  val urlvaluedef = url.asInstanceOf[Instance].defSite
                                                  val loc = url.asInstanceOf[Instance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluedef)
                                                  IndexMap(IndexMapK) += map
                                                }else{
                                                  val urlvalueelse = "ANY"
                                                  IndexMapV(i) = urlvalueelse
                                                }
                                              }
                                          }
                                      }
                                  }
                                }
                                IndexMap.keys.foreach{
                                  IndexMapK =>
                                    IndexMap(IndexMapK).foreach{
                                      IndexMapV =>
                                        IndexMapV.keys.foreach{
                                          i =>
                                            if(IndexMapV(i) == con){
                                              IndexMap(IndexMapK) -= IndexMapV
                                            }
                                        }
                                    }
                                }
                              }
                            }
                            /*********************/
                            if (size == 2){
                              var flag = true
                              var temp: Any = ""
                              urlMapModel.keys.foreach{
                                i =>
                                  if(i == con){
                                    temp = urlMapModel(i)
                                    IndexMap.keys.foreach{
                                      IndexMapK =>
                                        IndexMap(IndexMapK).foreach{
                                          IndexMapV =>
                                            IndexMapV.keys.foreach{
                                              i =>
                                                if(IndexMapV(i) == con){
                                                  IndexMapV(i) = temp
                                                  flag = false
                                                }
                                            }
                                        }
                                    }
                                  }
                              }
                              if (flag == true){
                                val urlSlot = VarSlot(cn.argNames.head)
                                val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                                val strSlot = VarSlot(cn.argNames(1))
                                val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext , strSlot)
                                for(url <- urlvalues /*++ urls*/) {
                                  IndexMap.keys.foreach{
                                    IndexMapK =>
                                      IndexMap(IndexMapK).foreach{
                                        IndexMapV =>
                                          IndexMapV.keys.foreach{
                                            i =>
                                              if(IndexMapV(i) == con){
                                                if(url.isInstanceOf[PTAConcreteStringInstance]){
                                                  val urlvaluestring = url.asInstanceOf[PTAConcreteStringInstance].string
                                                  val loc = url.asInstanceOf[PTAConcreteStringInstance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluestring)
                                                  IndexMap(IndexMapK) += map
                                                }else if (url.isInstanceOf[Instance])
                                                {
                                                  val urlvaluedef = url.asInstanceOf[Instance].defSite
                                                  val loc = url.asInstanceOf[Instance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluedef)
                                                  IndexMap(IndexMapK) += map
                                                }
                                              }
                                          }
                                      }
                                  }
                                }
                                IndexMap.keys.foreach{
                                  IndexMapK =>
                                    IndexMap(IndexMapK).foreach{
                                      IndexMapV =>
                                        IndexMapV.keys.foreach{
                                          i =>
                                            if(IndexMapV(i) == con){
                                              IndexMap(IndexMapK) -= IndexMapV
                                            }
                                        }
                                    }
                                }
                              }
                            }
                            /*********************/
                            if (size == 3){
                              var flag = true
                              var temp: Any = ""
                              urlMapModel.keys.foreach{
                                i =>
                                  if(i == con){
                                    temp = urlMapModel(i)
                                    IndexMap.keys.foreach{
                                      IndexMapK =>
                                        IndexMap(IndexMapK).foreach{
                                          IndexMapV =>
                                            IndexMapV.keys.foreach{
                                              i =>
                                                if(IndexMapV(i) == con){
                                                  IndexMapV(i) = temp
                                                  flag = false
                                                }
                                            }
                                        }
                                    }
                                  }
                              }
                              if (flag == true){
                                val urlSlot = VarSlot(cn.argNames.head)
                                val urls = idfg.ptaresult.pointsToSet(cn.getContext , urlSlot)
                                val strSlot3 = VarSlot(cn.argNames(1))
                                val urlvalues3 = idfg.ptaresult.pointsToSet(cn.getContext , strSlot3)
                                val strSlot4 = VarSlot(cn.argNames(2))
                                val urlvalues4 = idfg.ptaresult.pointsToSet(cn.getContext , strSlot4)
                                for(url <- urlvalues3 ++ urlvalues4) {
                                  IndexMap.keys.foreach{
                                    IndexMapK =>
                                      IndexMap(IndexMapK).foreach{
                                        IndexMapV =>
                                          IndexMapV.keys.foreach{
                                            i =>
                                              if(IndexMapV(i) == con){
                                                if(url.isInstanceOf[PTAConcreteStringInstance]){
                                                  val urlvaluestring = url.asInstanceOf[PTAConcreteStringInstance].string
                                                  val loc = url.asInstanceOf[PTAConcreteStringInstance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluestring)
                                                  IndexMap(IndexMapK) += map
                                                }else if (url.isInstanceOf[Instance])
                                                {
                                                  val urlvaluedef = url.asInstanceOf[Instance].defSite
                                                  val loc = url.asInstanceOf[Instance].defSite.getCurrentLocUri
                                                  val map:MMap[Any , Any] = mmapEmpty
                                                  map.getOrElseUpdate(loc , urlvaluedef)
                                                  IndexMap(IndexMapK) += map
                                                }else{
                                                  val urlvalueelse = "ANY"
                                                  IndexMapV(i) = urlvalueelse
                                                }
                                              }
                                          }
                                      }
                                  }
                                }
                                IndexMap.keys.foreach{
                                  IndexMapK =>
                                    IndexMap(IndexMapK).foreach{
                                      IndexMapV =>
                                        IndexMapV.keys.foreach{
                                          i =>
                                            if(IndexMapV(i) == con){
                                              IndexMap(IndexMapK) -= IndexMapV
                                            }
                                        }
                                    }
                                }
                              }
                            }
                          case _ =>
                        }
                    }
                  }
                  /*******Make sure there is no defsite in file names' Map**************/
                  context1.foreach{
                    i =>
                      i match{
                        case i1: Context =>
                        case i2: String => context1 -= i2
                        case _ =>
                      }
                  }
                  var temp: Any = ""
                  context1.foreach{
                    con =>
                      urlMapModel.keys.foreach{
                        i =>
                          if(i == con){
                            temp = urlMapModel(i)
                            IndexMap.keys.foreach{
                              IndexMapK =>
                                IndexMap(IndexMapK).foreach{
                                  IndexMapV =>
                                    IndexMapV.keys.foreach{
                                      i =>
                                        if(IndexMapV(i) == con){
                                          IndexMapV(i) = temp
                                        }
                                    }
                                }
                            }
                          }
                      }
                  }
                  /******************Make the output of the files' names with order*************************/
                  var loop: MSet[Any] = msetEmpty
                  IndexMap.keys.foreach{
                    IxMapK =>
                      L.foreach{
                        loop = msetEmpty
                        l =>
                          IndexMap(IxMapK).foreach{
                            i =>
                              i.keys.foreach{
                                j =>
                                  if(j == l && !loop.contains(j)){
                                    urlMapPlus.getOrElseUpdate(IxMapK, mlistEmpty) += i(j)
                                    loop += j
                                  }
                              }
                          }
                      }
                  }
                  /******************* Print file's name value *********************/
                  /*val gnpath = taint_analysis_result.getTaintedPaths.filter{
                    taintpath =>
                      taintpath.getSink.node.node match {
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileOutputStream;.write:([B)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/RandomAccessFile;.writeChar:(I)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/DataOutputStream;.writeBytes:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I") =>
                          true
                        case _ => false
                      }

                  }
                  val gisNodes = gnpath.map( i => i.getSink)*/
                  val gisNodes = taint_analysis_result.getSinkNodes.filter{
                    node =>
                      node.node.node match {
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileOutputStream;.write:([B)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/RandomAccessFile;.writeChar:(I)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/io/DataOutputStream;.writeBytes:(Ljava/lang/String;)V") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J") =>
                          true
                        case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I") =>
                          true
                        case _ => false
                      }
                  }
                  //if (compNum == realcompNnm){
                  println("*****************************************************")
                  gisNodes.foreach {
                    gisnode =>
                      if (gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/FileWriter;.write:(Ljava/lang/String;)V")
                        | gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;")
                        |gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;")
                        |gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/BufferedWriter;.write:(Ljava/lang/String;)V")
                        |gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Ljava/io/FileOutputStream;.write:([B)V")){
                        val invNode = gisnode.node.node.asInstanceOf[ICFGInvokeNode]
                        val connSlot = VarSlot(invNode.argNames.head)
                        val connValues = idfg.ptaresult.pointsToSet(invNode.getContext, connSlot)

                        connValues foreach {
                          urlValue =>
                            println("File's name at " + gisnode.descriptor + "@" + gisnode.node.node.getContext.getLocUri + "\nis:\n" + urlMapPlus.getOrElse(urlValue.defSite, mlistEmpty).mkString("\n")/*urlMap.getOrElse(urlValue.defSite, msetEmpty).mkString("\n")*/)
                        }
                      }
                      if (gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.update:(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I") |
                        gisnode.node.node.asInstanceOf[ICFGInvokeNode].getCalleeSig == new Signature("Landroid/database/sqlite/SQLiteDatabase;.insert:(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J")){
                        val invNode = gisnode.node.node.asInstanceOf[ICFGInvokeNode]
                        val connValues:MSet[Context] = msetEmpty
                        connValues += invNode.getContext
                        connValues foreach {
                          urlValue =>
                            println("DB Table's name at " + gisnode.descriptor + "@" + gisnode.node.node.getContext.getLocUri + "\nis:\n" + urlMapPlus.getOrElse(urlValue, mlistEmpty).mkString("\n"))
                            println("DB Table's structure " + "\nis:\n" + IndexMap2(urlMapPlus.getOrElse(urlValue, mlistEmpty).mkString))
                            println("DB Table's Database's name " + "\nmaybe is one of the following items:\n" + DB_Name.mkString(","))
                        }
                      }
                  }
                  println("Done!" +"\n"+ "*****************************************************")
                //}
                /*}catch{
                case e : Exception => println("There is some thing wrong with some component's taint analysis ：" + e)
                }*/
                case None =>
                  yard.reporter.error("TaintAnalysis", "Component " + iComponents + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
              }
            //}
        }
        //}
    }
    //}
  //}
}
