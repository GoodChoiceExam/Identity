FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY FitLife.Identity.slnx .
COPY FitLife.Identity.Api/FitLife.Identity.Api.csproj FitLife.Identity.Api/
COPY FitLife.Identity.Tests/FitLife.Identity.Tests.csproj FitLife.Identity.Tests/
RUN dotnet restore FitLife.Identity.slnx

COPY . .
RUN dotnet test FitLife.Identity.Tests/FitLife.Identity.Tests.csproj --no-restore
RUN dotnet publish FitLife.Identity.Api/FitLife.Identity.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "FitLife.Identity.Api.dll"]