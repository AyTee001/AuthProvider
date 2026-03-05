#Stage 1 - Build & Publish
FROM mcr.microsoft.com/dotnet/sdk:10.0 as build

WORKDIR /src

COPY  ["AuthProvider.Migrator/AuthProvider.Migrator.csproj", "AuthProvider.Migrator/"]
COPY  ["AuthProvider/AuthProvider.csproj", "AuthProvider/"]
RUN dotnet restore "AuthProvider.Migrator/AuthProvider.Migrator.csproj"

COPY ["AuthProvider.Migrator", "AuthProvider.Migrator/"]
COPY ["AuthProvider", "AuthProvider/"]

WORKDIR "/src/AuthProvider.Migrator"
RUN dotnet publish "AuthProvider.Migrator.csproj" -c Release -o /app/publish


#Stage 2 - Run
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "AuthProvider.Migrator.dll"]