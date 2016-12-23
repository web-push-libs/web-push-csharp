mkdir package\lib\net45
copy ..\src\bin\Release\WebPush.dll package\lib\net45
nuget pack package\WebPush.nuspec