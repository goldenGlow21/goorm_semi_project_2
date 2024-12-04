import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableHead, TableBody, TableCell, TableContainer, TableRow, Paper,
          Typography, Box, Button, Pagination, TableFooter } from "@mui/material";
import { errorAlert } from "./component/Alert";

const RecentScan = () => {
  const [basicData, setBasicData] = useState([]);
  const [additionalData, setAdditionalData] = useState([]);
  const [basicPage, setBasicPage] = useState(1);
  const [additionalPage, setAdditionalPage] = useState(1);
  const rowsPerPage = 10; // Number of rows per page
  const navigate = useNavigate();

  // Logs와 Service Logs 데이터를 가져와 병합하는 함수
  const fetchAllData = async () => {
    try {
      const [logsResponse, serviceLogsResponse] = await Promise.all([
        fetch("http://localhost:5000/logs"),
        fetch("http://localhost:5000/service_logs"),
      ]);

      if (logsResponse.status === 200 && serviceLogsResponse.status === 200) {
        const logsData = await logsResponse.json();
        const serviceLogsData = await serviceLogsResponse.json();

        setBasicData(logsData);
        setAdditionalData(serviceLogsData);
      } else {
        throw new Error(
          `HTTP error! Logs: ${logsResponse.status}, Service Logs: ${serviceLogsResponse.status}`
        );
      }
    } catch (err) {
      console.error("Error fetching data:", err);
      errorAlert("데이터를 불러오는 중 오류가 발생했습니다.");
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const handleRowClick = (rowData) => {
    navigate('/scanResult', { state: { ip: rowData.ip, 
                                    scan_type: rowData.scan_type,
                                    scan_time: rowData.scan_time,
                                    additional_info: rowData.cves } });
  };

  const formatList = (list, maxLength) => {
    if (!Array.isArray(list) || list.length === 0) return "NULL";
    return list.length > maxLength
      ? `${list.slice(0, maxLength).join(", ")} ...`
      : list.join(", ");
  };

  // Page change handlers
  const handleBasicPageChange = (event, value) => setBasicPage(value);
  const handleAdditionalPageChange = (event, value) => setAdditionalPage(value);

  
  return (
    <div className="scan-result-container">
      <header className="header">
        <div className="logo">
          <img src="/goormton.png" alt="Logo" />
        </div>
        <h1>Port Scanning Project</h1>
        <Box>
          <Button
            variant="contained"
            color="secondary"
            onClick={fetchAllData}
            sx={{ marginRight: 1 }}
          >
            Reload
          </Button>
          <Button
            variant="contained"
            color="info"
            onClick={() => navigate("/")}
          >
            MainBoard
          </Button>
        </Box>
      </header>
      <div className="divider"></div>

      <div className="table-container">
        <Typography variant="h6">Basic Information</Typography>
        <TableContainer component={Paper} sx={{ marginBottom: 3 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>IP</TableCell>
                <TableCell>Open Ports</TableCell>
                <TableCell>Open or Filtered</TableCell>
                <TableCell>Scan Type</TableCell>
                <TableCell>Scan Time</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {basicData.map((row, index) => (
                <TableRow
                  key={index}
                  onClick={() => handleRowClick(row, "Basic Information")}
                  sx={{ cursor: 'pointer' }}
                >                  
                  <TableCell>{row.ip}</TableCell>
                  <TableCell>{formatList(row.open, 5)}</TableCell>
                  <TableCell>{formatList(row.open_or_filtered, 5)}</TableCell>
                  <TableCell>{row.scan_type}</TableCell>
                  <TableCell>{new Date(row.scan_time).toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
            <TableFooter>
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Pagination
                    count={Math.ceil(basicData.length / rowsPerPage)}
                    page={basicPage}
                    onChange={handleBasicPageChange}
                    color="primary"
                  />
                </TableCell>
              </TableRow>
            </TableFooter>
          </Table>
        </TableContainer>


        <Typography variant="h6" sx={{ marginTop: 4 }}>
          Additional Information
        </Typography>
        <TableContainer component={Paper} style={{ marginTop: '20px' }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>IP 주소</TableCell>
                <TableCell>스캔 타입</TableCell>
                <TableCell>스캔 시간</TableCell>
                <TableCell align="center">열린 포트 수</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {additionalData.map((item, index) => (
                <TableRow
                  key={index}
                  hover
                  onClick={() => handleRowClick(item)}
                  style={{ cursor: 'pointer' }}
                >
                  <TableCell>{item.ip}</TableCell>
                  <TableCell>{item.scan_type}</TableCell>
                  <TableCell>{new Date(item.scan_time).toLocaleString()}</TableCell>
                  <TableCell align="center">{item.cves?.length || 0}</TableCell>
                </TableRow>
              ))}
            </TableBody>
            <TableFooter>
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Pagination
                    count={Math.ceil(additionalData.length / rowsPerPage)}
                    page={additionalPage}
                    onChange={handleAdditionalPageChange}
                    color="secondary"
                  />
                </TableCell>
              </TableRow>
            </TableFooter>
          </Table>
        </TableContainer>

      </div>
    </div>
  );
};

export default RecentScan;
