IF NOT DEFINED JAVA_HEAP_SIZE (
  SET JAVA_HEAP_SIZE=1024m
)
IF NOT DEFINED RESERVED_CODE_CACHE_SIZE (
  SET RESERVED_CODE_CACHE_SIZE=300m
)
set PROJECT_DIR=%~dp0\..\..
set SBT_DIR=%PROJECT_DIR%\sbt
java -Dfile.encoding=UTF8 %JAVA_OPTS% -XX:ReservedCodeCacheSize=%RESERVED_CODE_CACHE_SIZE% -Xss128M -XX:+CMSClassUnloadingEnabled -Xmx%JAVA_HEAP_SIZE% -jar %PROJECT_DIR%\tools\bin\sbt-launch.jar %SBT_OPTS% %*