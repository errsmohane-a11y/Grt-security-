using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GRT.Security.Platform.Migrations
{
    /// <inheritdoc />
    public partial class AddDetailsToSecurityLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Details",
                table: "SecurityLogs",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Details",
                table: "SecurityLogs");
        }
    }
}
