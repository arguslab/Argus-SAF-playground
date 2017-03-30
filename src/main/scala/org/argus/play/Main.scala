package org.argus.play

import org.apache.commons.cli._
import org.argus.play.random.{CountComponentNum, NativeStatistics, SecurityAnalysis}
import org.sireum.util._

/**
  * Created by fgwei on 3/8/17.
  */
object Main extends App {
  private val version = org.argus.BuildInfo.version

  object Mode extends Enumeration {
    val ARGUS_SAF_PLAY, NATIVE_STATISTICS, COUNT_COMPONENT_NUM, SECURITY_ANALYSIS = Value
  }

  private val nativeStatisticsOptions: Options = new Options
  private val securityAnalysisOptions: Options = new Options
  private val allOptions: Options = new Options

  private def createOptions(): Unit = {
    // create options
    val versionOption: Option = Option.builder().longOpt("version").desc("Prints the version then exits.").build()

    val startNumOption: Option = Option.builder("n").longOpt("num").desc("Start from num file in the list.").hasArg(true).argName("startNum").build()
    val genReportOption: Option = Option.builder("g").longOpt("gen").desc("Generate native lib usage report.").build()
    val calculateOption: Option = Option.builder("c").longOpt("calculate").desc("Calculate native lib usage statistics.").build()
    val checkersOption: Option = Option.builder("checker").desc("Select checkers separated by ',' (e.g., '1,2') for security analysis. Available checkers: 1. Hide Icon; 2. Crypto Misuse; 3. SSL/TLS Misuse; 4. Communication Leak; 5. Intent Injection.").hasArg(true).argName("nums").build()
    nativeStatisticsOptions.addOption(startNumOption)
    nativeStatisticsOptions.addOption(genReportOption)
    nativeStatisticsOptions.addOption(calculateOption)
    securityAnalysisOptions.addOption(startNumOption)
    securityAnalysisOptions.addOption(checkersOption)
    allOptions.addOption(versionOption)
    allOptions.addOption(startNumOption)
    allOptions.addOption(genReportOption)
    allOptions.addOption(calculateOption)
    allOptions.addOption(checkersOption)
  }

  private def usage(mode: Mode.Value): Unit = {
    val formatter: HelpFormatter = new HelpFormatter
    formatter.setWidth(120)
    mode match {
      case Mode.ARGUS_SAF_PLAY =>
        println(s"""Argus-SAF-playground v$version - playground for Argus-SAF
                   |Copyright 2017 Argus Laboratory, University of South Florida""".stripMargin)
        println("")
        println("""Available Modes:
                  |  c[ount_component_num]  Count component numbers for given apks.
                  |  n[ative_statistics]    Generate statistics for native lib usage of given dataset.
                  |  s[ecurity_analysis]    Perform security analysis.""".stripMargin)
        println("")
      case Mode.NATIVE_STATISTICS =>
        formatter.printHelp("n[ative_statistics] <file_apk/dir> <output_dir>", nativeStatisticsOptions)
      case Mode.COUNT_COMPONENT_NUM =>
        println("c[ount_component_num] <file_apk/dir> <output_dir> <file>")
      case Mode.SECURITY_ANALYSIS =>
        formatter.printHelp("s[ecurity_analysis] <file_apk/dir> <output_dir>", securityAnalysisOptions)
    }
  }

  // create the command line parser
  val parser: CommandLineParser = new DefaultParser()
  var commandLine: CommandLine = _

  createOptions()

  try {
    // parse the command line arguments
    commandLine = parser.parse(allOptions, args)
  }
  catch {
    case exp: ParseException =>
      println("ParseException:" + exp.getMessage)
      usage(Mode.ARGUS_SAF_PLAY)
      System.exit(1)
  }

  var cmdFound: Boolean = false

  try {
    for (opt <- commandLine.getArgs) {
      if (opt.equalsIgnoreCase("n") || opt.equalsIgnoreCase("native_statistics")) {
        cmdNativeStatistics(commandLine)
        cmdFound = true
      } else if (opt.equalsIgnoreCase("c") || opt.equalsIgnoreCase("count_component_num")) {
        cmdCountComponentNum(commandLine)
        cmdFound = true
      } else if (opt.equalsIgnoreCase("s") || opt.equalsIgnoreCase("security_analysis")) {
        cmdSecurityAnalysis(commandLine)
        cmdFound = true
      }
    }
  } catch {
    case exp: Exception =>
      println("Unexpected exception:" + exp.getMessage)
  } finally {
    // if no commands ran, run the version / usage check.
    if (!cmdFound) {
      if (commandLine.hasOption("-v") || commandLine.hasOption("--version")) {
        println("Argus-SAF v" + version)
      }
      else {
        usage(Mode.ARGUS_SAF_PLAY)
      }
    }
  }

  case class ArgNotEnoughException(msg: String) extends Exception(msg)

  private def cmdNativeStatistics(cli: CommandLine) = {
    var outputPath: String = "."
    var sourcePath: String = null
    var startNum: Int = 0
    var genReport: Boolean = false
    var cacReport: Boolean = false
    if(cli.hasOption("n") || cli.hasOption("num")) {
      startNum = Integer.parseInt(cli.getOptionValue("n"))
    }
    if(cli.hasOption("g") || cli.hasOption("gen")) {
      genReport = true
    }
    if(cli.hasOption("c") || cli.hasOption("calculate")) {
      cacReport = true
    }
    try {
      sourcePath = cli.getArgList.get(1)
      outputPath = cli.getArgList.get(2)
    } catch {
      case _: Exception =>
        usage(Mode.NATIVE_STATISTICS)
        System.exit(0)
    }
    if(genReport)
      NativeStatistics(sourcePath, outputPath, startNum)
    if(cacReport)
      NativeStatistics(outputPath)
  }

  private def cmdCountComponentNum(cli: CommandLine) = {
    var outputPath: String = "."
    var sourcePath: String = null
    var file: String = null
    try {
      sourcePath = cli.getArgList.get(1)
      outputPath = cli.getArgList.get(2)
      file = cli.getArgList.get(3)
    } catch {
      case _: Exception =>
        usage(Mode.COUNT_COMPONENT_NUM)
        System.exit(0)
    }
    CountComponentNum(sourcePath, outputPath, file)
  }

  private def cmdSecurityAnalysis(cli: CommandLine) = {
    var outputPath: String = "."
    var sourcePath: String = null
    var startNum: Int = 0
    var checkers: IList[Int] = ilistEmpty
    if(cli.hasOption("n") || cli.hasOption("num")) {
      startNum = Integer.parseInt(cli.getOptionValue("n"))
    }
    if(cli.hasOption("checker")) {
      checkers = cli.getOptionValue("checker").split(",").map(Integer.parseInt).toList
    }
    try {
      sourcePath = cli.getArgList.get(1)
      outputPath = cli.getArgList.get(2)
    } catch {
      case _: Exception =>
        usage(Mode.SECURITY_ANALYSIS)
        System.exit(0)
    }
    SecurityAnalysis(sourcePath, outputPath, checkers, startNum)
  }
}
