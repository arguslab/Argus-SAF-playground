package org.argus.play.util

import java.io.File

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.jawa.core.{Constants, Global, Reporter}
import org.sireum.util.{FileResourceUri, FileUtil}

/**
  * Created by fgwei on 3/8/17.
  */
object Utils {

  def loadApk(apkUri: FileResourceUri, settings: DecompilerSettings, collectInfo: Boolean, reporter: Reporter): ApkGlobal = {
    val (outUri, srcs, _) = ApkDecompiler.decompile(apkUri, settings)
    val apk = new ApkGlobal(ApkModel(apkUri, outUri, srcs), reporter)
    srcs foreach {
      src =>
        val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
        if(FileUtil.toFile(fileUri).exists()) {
          //store the app's jawa code in AmandroidCodeSource which is organized class by class.
          apk.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
        }
    }
    if(collectInfo)
      AppInfoCollector.collectInfo(apk, outUri)
    apk
  }
}
