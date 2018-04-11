package org.argus.play.random

import java.io.{FileReader, FileWriter, PrintWriter}

import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.json4s._
import org.json4s.native.{JsonParser, Serialization}
import org.json4s.native.Serialization.write

object ReflectionMethodProcessor {
  def main(args: Array[String]):  Unit = {
    val baseUri = FileUtil.toUri(args(0))
    val outUri = FileUtil.toUri(args(1))
    val files = FileUtil.listFiles(baseUri, ".json", recursive = true).filter(f => f.contains("report"))

    var totalFN = 0
    var haveRef = 0
    var totalRef = 0
    var haveExc = 0
    var cannotResolve = 0

    var totalSystemRef = 0

    println(files.size)

    val global = new Global("statistics", new DefaultReporter)
    global.setJavaLib(AndroidGlobalConfig.settings.lib_files)

    //             File           So          Fn           Typ
    val data: MMap[String, MMap[String, MMap[String, MMap[String, MList[String]]]]] = mmapEmpty

    val systemApiList: MSet[String] = msetEmpty
    val customList: MSet[String] = msetEmpty

    files.foreach { f =>
      val obj = JsonParser.parse(FileUtil.readFile(new FileReader(FileUtil.toFile(f))))
      obj match {
        case arr: JArray =>
          arr(0) match {
            case str: JString =>
              val apkName = str.s
              val soMap = data.getOrElseUpdate(apkName, mmapEmpty)
              arr(1) match {
                case sos: JObject =>
                  sos.obj.foreach {
                    case (soName: String, so: JObject) =>
                      val fnMap = soMap.getOrElseUpdate(soName, mmapEmpty)
                      so.obj.foreach {
                        case (funName: String, detail: JObject) =>
                          totalFN += 1
                          val typMap = fnMap.getOrElseUpdate(funName, mmapEmpty)
                          detail.obj.foreach {
                            case (ref: String, jniFns: JObject) if ref == "reflection_call_accuracy" =>
                              if(jniFns.obj.nonEmpty) {
                                haveRef += 1
                                jniFns.obj.foreach {
                                  case (_: String, parts: JArray) =>
                                    totalRef += 1
                                    if(parts.arr.size != 3) {
                                      println("error!!!!!")
                                    } else {
                                      parts(0) match {
                                        case classStr: JString if classStr.s.nonEmpty =>
                                          val typ = JavaKnowledge.getTypeFromJawaName(classStr.s.replaceAll("/", "."))
                                          val classPart = JavaKnowledge.formatTypeToSignature(typ)
                                          parts(1) match {
                                            case methodStr: JString =>
                                              val methodPart = methodStr.s
                                              parts(2) match {
                                                case paramStr: JString =>
                                                  val paramPart = paramStr.s
                                                  val sig = new Signature(s"$classPart.$methodPart:$paramPart")
                                                  if(global.containsClass(new JawaType(sig.classTyp.baseTyp))) {
                                                    totalSystemRef += 1
                                                    typMap.getOrElseUpdate("system", mlistEmpty).append(sig.signature)
                                                    systemApiList += sig.signature
                                                  } else {
                                                    typMap.getOrElseUpdate("custom", mlistEmpty).append(sig.signature)
                                                    customList += sig.signature
                                                  }
                                                case _ => cannotResolve += 1
                                              }
                                            case _ => cannotResolve += 1
                                          }
                                        case _ => cannotResolve += 1
                                      }
                                    }
                                  case _ =>
                                }
                              }
                            case (ex: String, _) if ex == "exception" =>
                              haveExc += 1
                            case _ =>
                          }
                        case _ =>
                      }
                    case _ =>
                  }
                case _ =>
              }
            case _ =>
          }
        case _ =>
      }
    }
    val apkRes = FileUtil.toFile(FileUtil.appendFileName(outUri, "resolvedReflectionDetail.json"))
    val oapk = new PrintWriter(apkRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints)
    try {
      write(data, oapk)
    } catch {
      case e: Exception =>
        apkRes.delete()
        throw e
    } finally {
      oapk.flush()
      oapk.close()
    }

    val report_fileuri = FileUtil.appendFileName(outUri, "reflectionStatistics.ini")
    val writer = new FileWriter(FileUtil.toFile(report_fileuri), false)
    try {
      writer.write("[statistic]\n")
      writer.write("Total_JNI_Function = " + totalFN + "\n")
      writer.write("Have_Reflection_Call = " + haveRef + "\n")
      writer.write("Timeout = " + haveExc + "\n")
      writer.write("Total_Reflection_Call = " + totalRef + "\n")
      writer.write("Total_System_API_Call = " + totalSystemRef + "\n")
      writer.write("Total_Custom_Call = " + (totalRef - totalSystemRef - cannotResolve) + "\n")
      writer.write("Cannot_Resolve_Reflection_Call = " + cannotResolve + "\n")
    } catch {
      case e: Exception =>
        throw e
    } finally {
      writer.close()
    }

    val sysListFile = FileUtil.appendFileName(outUri, "systemReflectionList.txt")
    val sysWriter = new FileWriter(FileUtil.toFile(sysListFile), false)
    try {
      sysWriter.write(systemApiList.toList.sorted.mkString("\n"))
    } catch {
      case e: Exception =>
        throw e
    } finally {
      sysWriter.close()
    }

    val cusListFile = FileUtil.appendFileName(outUri, "customReflectionList.txt")
    val cusWriter = new FileWriter(FileUtil.toFile(cusListFile), false)
    try {
      cusWriter.write(customList.toList.sorted.mkString("\n"))
    } catch {
      case e: Exception =>
        throw e
    } finally {
      cusWriter.close()
    }

  }
}
