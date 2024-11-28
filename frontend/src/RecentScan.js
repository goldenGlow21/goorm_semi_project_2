import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableHead, TableBody, TableCell, TableContainer, TableRow, Paper, Typography, Box, Button } from "@mui/material";

const RecentScan = () => {
  const [recentScanData, setRecentScanData] = useState([]);
  const [error, setError] = useState(null); // 오류 상태 추가
  const navigate = useNavigate();

  /* API 호출 */
  const fetchRecentScanData = async () => {
    try {
      const response = await fetch("http://localhost:5000/recentScan"); // /recentScan API 호출
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json(); // JSON 데이터를 파싱
      setRecentScanData(data); // 상태에 저장
      // 이게 어떻게 저장되는지를 보고 파싱할 정보들을 나열하면 될 듯 하다.
    } catch (err) {
      console.error("Error fetching scan data:", err);
      setError("Unable to fetch scan data."); // 오류 메시지 저장
    }
  };

  /* 렌더링 될 때마다 호출 */
  useEffect(() => {
    fetchRecentScanData();
  }, []);

  const handleRowClick = (recentScan) => {
    navigate("/scanResult", { state: { ...recentScan, type: "recentScan" } }); // 스캔 데이터를 전달하며 이동
  };

  return (
    <div
      className="scan-result-container"
      style={{ padding: 3, backgroundColor: "#f5f5f5", minHeight: "100vh" }}
    >
      {/* Header Section */}
      <Box
        className="header"
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          backgroundColor: "#1976d2",
          padding: 2,
          borderRadius: 1,
          marginBottom: 3,
        }}
      >
        <Box className="logo" sx={{ display: "flex", alignItems: "center" }}>
          <img
            src="/goormton.png"
            alt="Logo"
            style={{ height: "50px", marginRight: "10px" }}
          />
          <Typography variant="h5" color="white">
            Port Scanning Project
          </Typography>
        </Box>
        <Box>
          <Button
            variant="contained"
            color="secondary"
            onClick={fetchRecentScanData}
            sx={{ marginRight: 1 }}
          >
            Reload
          </Button>
          <Button variant="contained" color="info" onClick={() => navigate("/")}>
            MainBoard
          </Button>
        </Box>
      </Box>

      {/* Table Section */}
      <div>
        <h1>Recent Scans</h1>
        {error ? (
          <Typography color="error">{error}</Typography>
        ) : recentScanData.length === 0 ? (
          <Typography>No recent scans available.</Typography> // 데이터가 없을 때 메시지
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Date</TableCell>
                  <TableCell>IP</TableCell>
                  <TableCell>Start Port</TableCell>
                  <TableCell>End Port</TableCell>
                  <TableCell>Scan Type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {recentScanData.map((scanData, index) => (
                  <TableRow
                    key={index}
                    onClick={() => handleRowClick(scanData)}
                    style={{ cursor: "pointer" }}
                  >
                    <TableCell>{scanData.date || "NULL"}</TableCell>
                    <TableCell>{scanData.ip || "NULL"}</TableCell>
                    <TableCell>{scanData.startPort || "NULL"}</TableCell>
                    <TableCell>{scanData.endPort || "NULL"}</TableCell>
                    <TableCell>{scanData.scanType || "NULL"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </div>
    </div>
  );
};

export default RecentScan;
