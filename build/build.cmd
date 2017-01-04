mkdir package\lib\net40
copy ..\src\bin\Release\WebPush.dll package\lib\net40
nuget pack package\WebPush.nuspec