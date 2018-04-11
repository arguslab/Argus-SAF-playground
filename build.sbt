import Common._
import sbt.Keys._
import sbtassembly.AssemblyPlugin.autoImport._
import sbtbuildinfo.BuildInfoPlugin.autoImport._

resolvers := Seq("Repo Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local")

val argusSafPlaySettings = Defaults.coreDefaultSettings ++ Seq(
  libraryDependencies += "org.scala-lang" % "scala-compiler" % ArgusVersions.scalaVersion,
  scalacOptions ++= Seq("-unchecked", "-deprecation", "-feature")
)
val buildInfoSettings = Seq(
  // build info
  buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion),
  buildInfoPackage := "org.argus"
)
val assemblySettings = Seq(
  assemblyJarName in assembly := s"${name.value}-${version.value}-assembly.jar",
  mainClass in assembly := Some("org.argus.play.cli.Main")
)

lazy val argus_saf_play: Project =
  newProject("argus-saf-playground", file("."))
    .enablePlugins(BuildInfoPlugin)
    .settings(libraryDependencies ++= DependencyGroups.saf_play)
    .settings(argusSafPlaySettings)
    .settings(buildInfoSettings)
    .settings(assemblySettings)
    .settings(
      artifact in (Compile, assembly) ~= { art =>
        art.withClassifier(Some("assembly"))
      },
      addArtifact(artifact in (Compile, assembly), assembly),
      publishArtifact in (Compile, packageBin) := false,
      publishArtifact in (Compile, packageDoc) := false,
      publishArtifact in (Compile, packageSrc) := false
    )