FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ./ /src
RUN dotnet restore
COPY . .
RUN dotnet build -c Release

WORKDIR "/src/Reflective"
RUN dotnet build "./Reflective.csproj" -c Release -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Reflective.csproj" -c Release -o /app/publish /p:UseAppHost=false
COPY --from=build /src/BookKeeper/bin/Release/net9.0/BookKeeper.dll /app/publish/BookKeeper.dll

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
RUN apt update && apt install -y curl
ENTRYPOINT ["dotnet", "Reflective.dll"]



