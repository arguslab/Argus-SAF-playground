package org.argus.play

import org.apache.commons.cli._
import org.argus.play.random.NativeStatistics

/**
  * Created by fgwei on 3/8/17.
  */
object Main extends App {
  private val version = org.argus.BuildInfo.version

  object Mode extends Enumeration {
    val ARGUS_SAF_PLAY, NATIVE_STATISTICS = Value
  }

  private val nativeStatisticsOptions: Options = new Options
  private val allOptions: Options = new Options

  private def createOptions(): Unit = {
    // create options
    val versionOption: Option = Option.builder().longOpt("version").desc("Prints the version then exits.").build()

    val genReportOption: Option = Option.builder("g").longOpt("gen").desc("Generate native lib usage report.").build()
    val caculateOption: Option = Option.builder("c").longOpt("calculate").desc("Caculate native lib usage statistics.").build()
    nativeStatisticsOptions.addOption(genReportOption)
    nativeStatisticsOptions.addOption(caculateOption)
    allOptions.addOption(versionOption)
    allOptions.addOption(genReportOption)
    allOptions.addOption(caculateOption)
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
                  |  n[ative_statistics]    Generate statistics for native lib usage of given dataset.""".stripMargin)
        println("")
      case Mode.NATIVE_STATISTICS =>
        formatter.printHelp("n[ative_statistics] <file_apk/dir> <output_dir>", nativeStatisticsOptions)
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
    var genReport: Boolean = false
    var cacReport: Boolean = false
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
      NativeStatistics(sourcePath, outputPath)
    if(cacReport)
      NativeStatistics(outputPath)
  }
}
