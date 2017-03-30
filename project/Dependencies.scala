import sbt._

object ArgusVersions {
  val scalaVersion = "2.11.8"
  val sbtVersion = "0.13.13"
}

object Dependencies {
  import ArgusVersions._

  val sbtLaunch: ModuleID = "org.scala-sbt" % "sbt-launch" % sbtVersion

  val scala_reflect: ModuleID = "org.scala-lang" % "scala-reflect" % scalaVersion

  val commons_cli: ModuleID = "commons-cli" % "commons-cli" % "1.3.1"

  val amandroid_core: ModuleID = "com.github.arguslab" %% "amandroid-core" % "2.0.4"
}

object DependencyGroups {
  import Dependencies._

  val saf_play = Seq(
    scala_reflect,
    commons_cli,
    amandroid_core
  )
}