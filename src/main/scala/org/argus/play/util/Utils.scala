package org.argus.play.util

import java.io.File

import org.argus.amandroid.core.Apk
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompilerSettings}
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.jawa.core.{Constants, Global}
import org.sireum.util.{FileResourceUri, FileUtil, ISet}

/**
  * Created by fgwei on 3/8/17.
  */
object Utils {
  def loadCode(apkUri: FileResourceUri, settings: DecompilerSettings, global: Global): (FileResourceUri, ISet[String]) = {
    val (outUri, srcs, _) = ApkDecompiler.decompile(apkUri, settings)
    srcs foreach {
      src =>
        val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
        if(FileUtil.toFile(fileUri).exists()) {
          //store the app's jawa code in global which is organized class by class.
          global.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
        }
    }
    (outUri, srcs)
  }

  def loadApk(apkUri: FileResourceUri, settings: DecompilerSettings, global: Global, collectInfo: Boolean): Apk = {
    val (outUri, srcs) = loadCode(apkUri, settings, global)
    val apk = new Apk(apkUri, outUri, srcs)
    if(collectInfo)
      AppInfoCollector.collectInfo(apk, global, outUri)
    apk
  }
}
