import sbt._

object ArgusVersions {
  val scalaVersion = "2.12.4"
  val sbtVersion = "1.1.1"
}

object Dependencies {
  import ArgusVersions._

  val sbtLaunch: ModuleID = "org.scala-sbt" % "sbt-launch" % sbtVersion

  val commons_cli: ModuleID = "commons-cli" % "commons-cli" % "1.3.1"

  val amandroid_core: ModuleID = "com.github.arguslab" %% "amandroid" % "3.1.3-SNAPSHOT"
}

object DependencyGroups {
  import Dependencies._

  val saf_play = Seq(
    commons_cli,
    amandroid_core
  )
}