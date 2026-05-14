using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MACRiverProxy.Migrations
{
    /// <inheritdoc />
    public partial class AddUserIdentifierfield : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "UserIdentifier",
                table: "ActiveTokens",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UserIdentifier",
                table: "ActiveTokens");
        }
    }
}
