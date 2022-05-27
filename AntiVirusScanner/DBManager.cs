using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;

namespace AntiVirusScanner
{
    public class DBManager
    {
        static string connectionString = @"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=C:\Users\zkons\source\repos\Antiviurs_scanner\AntiVirusScanner\VirusDB.mdf;Integrated Security=True";
        SqlConnection cnn = new SqlConnection(connectionString);
        public void ConnectDB()
        {
            cnn.Open();
        }
        public void DisconnectDB()
        {
            cnn.Close();
        }
        public string GetVs()
        {
            SqlCommand cmd = new SqlCommand();
            SqlDataReader rdr;
            string sql = "SELECT VirusSeq FROM VirusSequences";
            string output="";
            cmd = new SqlCommand(sql,cnn);
            
            rdr = cmd.ExecuteReader();
            while (rdr.Read())
            {
                output= output + rdr.GetString(0) + '\n';
                
            }
            return output;
        }
    }
}
