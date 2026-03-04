#Stage 1 - Build & Publish
FROM mcr.microsoft.com/dotnet/sdk:10.0 as build

WORKDIR /src

COPY  ["AuthProvider/AuthProvider.csproj", "AuthProvider/"]
RUN dotnet restore "AuthProvider/AuthProvider.csproj"

COPY ["AuthProvider", "AuthProvider/"]

WORKDIR "/src/AuthProvider"
RUN dotnet publish "AuthProvider.csproj" -c Release -o /app/publish


#Stage 2 - Run
FROM mcr.microsoft.com/dotnet/aspnet:10.0
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "AuthProvider.dll"]
