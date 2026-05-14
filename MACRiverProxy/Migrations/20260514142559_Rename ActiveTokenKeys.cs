using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MACRiverProxy.Migrations
{
    /// <inheritdoc />
    public partial class RenameActiveTokenKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_ActiveTokens",
                table: "ActiveTokens");

            migrationBuilder.RenameTable(
                name: "ActiveTokens",
                newName: "ActiveTokenKeys");

            migrationBuilder.AddPrimaryKey(
                name: "PK_ActiveTokenKeys",
                table: "ActiveTokenKeys",
                column: "Key");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_ActiveTokenKeys",
                table: "ActiveTokenKeys");

            migrationBuilder.RenameTable(
                name: "ActiveTokenKeys",
                newName: "ActiveTokens");

            migrationBuilder.AddPrimaryKey(
                name: "PK_ActiveTokens",
                table: "ActiveTokens",
                column: "Key");
        }
    }
}
