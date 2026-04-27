using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MACRiverProxy.Migrations.LocalAuthStorageMigrations
{
    /// <inheritdoc />
    public partial class LocalAuthStorageadded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Login = table.Column<string>(type: "TEXT", nullable: false),
                    MACLevel = table.Column<byte>(type: "INTEGER", nullable: false),
                    MACCategory = table.Column<ulong>(type: "INTEGER", nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Login);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
