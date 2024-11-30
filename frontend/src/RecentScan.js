import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableHead, TableBody, TableCell, TableContainer, TableRow, Paper, Typography, Box, Button } from "@mui/material";
import { errorAlert } from "./component/Alert";

const RecentScan = () => {
  const [recentScanData, setRecentScanData] = useState([]);
  const [error, setError] = useState(null); // 오류 상태 추가
  const navigate = useNavigate();

  /* API 호출 */
  const fetchRecentScanData = async () => {
    try {
      const response = await fetch("http://localhost:5000/logs"); // /recentScan API 호출
      
      if (response.status === 200) {
        const data = await response.json(); // JSON 데이터를 파싱
        setRecentScanData(data); // 상태에 저장
      } else {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
    } catch (err) {
      console.error("Error fetching scan data:", err);
      setError("스캔 데이터를 불러오지 못했습니다.");
      errorAlert("스캔 데이터를 불러오지 못했습니다.");
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
    <div className="scan-result-container">
      {/* 상단 헤더 */}
      <header className="header">
        <div className="logo">
          <img src="/goormton.png" alt="Logo" />
        </div>
        <h1>Port Scanning Project</h1>
        <Box>
          <Button variant="contained" color="secondary" onClick={fetchRecentScanData} sx={{ marginRight: 1 }}>
            Reload
          </Button>
          <Button variant="contained" color="info" onClick={() => navigate("/")}>
            MainBoard
          </Button>
        </Box>
      </header>
      <div className="divider"></div>

      {/* Table Section */}
      <div className="table-container">
        <h1>Recent Scans</h1>
        {error
         ? ( <Typography color="error">{error}</Typography> )
         : recentScanData.length === 0
          ? ( <Typography>No recent scans available.</Typography> ) // 데이터가 없을 때 메시지
          :
        ( <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Date</TableCell>
                  <TableCell>IP</TableCell>
                  <TableCell>Open Ports</TableCell>
                  <TableCell>Open or Filtered Ports</TableCell>
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
                    <TableCell>{scanData.scan_time || "NULL"}</TableCell>
                    <TableCell>{scanData.ip || "NULL"}</TableCell>
                    <TableCell>{scanData.open || "NULL"}</TableCell>
                    <TableCell>{scanData.open_or_filtered || "NULL"}</TableCell>
                    <TableCell>{scanData.scan_type || "NULL"}</TableCell>
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
