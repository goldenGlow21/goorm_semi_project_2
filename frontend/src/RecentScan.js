import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableHead, TableBody, TableCell, TableContainer, TableRow, Paper,
          Typography, Box, Button, Pagination,} from "@mui/material";
import { errorAlert } from "./component/Alert";

const RecentScan = () => {
  const [combinedData, setCombinedData] = useState([]);
  const [error, setError] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(20);
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
        // 데이터가 어떻게 표현되는지 확인, 시간, type 모두 제대로 할당하기


        console.log("서비스 데이터", serviceLogsData);

        const combined = [
          ...logsData.map((item) => ({ ...item, type: "Basic Information" })),
          ...serviceLogsData.map((item) => ({ ...item, type: "Additional Information" })),
        ];

        setCombinedData(combined);
        setError(null);
      } else {
        throw new Error(
          `HTTP error! Logs: ${logsResponse.status}, Service Logs: ${serviceLogsResponse.status}`
        );
      }
    } catch (err) {
      console.error("Error fetching data:", err);
      setError("데이터를 불러오는 중 오류가 발생했습니다.");
      errorAlert("데이터를 불러오는 중 오류가 발생했습니다.");
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const handlePageChange = (event, value) => {
    setCurrentPage(value);
  };

  const currentData = combinedData.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const formatList = (list, maxLength) => {
    if (!Array.isArray(list) || list.length === 0) return "NULL";
    return list.length > maxLength
      ? `${list.slice(0, maxLength).join(", ")} ...`
      : list.join(", ");
  };

  const formatCVEs = (cves) => {
    if (!Array.isArray(cves) || cves.length === 0) return "No CVEs";
    return cves
      .slice(0, 3) // 최대 3개까지만 표시
      .map(
        (cve) =>
          `${cve.cve_id} (CVSS: ${cve.cvss || "N/A"}) - ${
            cve.summary ? cve.summary.slice(0, 50) + "..." : "No summary"
          }`
      )
      .join("\n");
  };

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
        <h1>Logs</h1>
        {error ? (
          <Typography color="error">{error}</Typography>
        ) : combinedData.length === 0 ? (
          <Typography>No data available.</Typography>
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Date</TableCell>
                  <TableCell>IP</TableCell>
                  <TableCell>Open Ports</TableCell>
                  <TableCell>Open or Filtered Ports</TableCell>
                  <TableCell>Scan Type</TableCell>
                  <TableCell>Detail Port Info</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Service</TableCell>
                  <TableCell>Version</TableCell>
                  <TableCell>CPE</TableCell>
                  <TableCell>Info</TableCell>
                  <TableCell>CVEs</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {currentData.map((data, index) => (
                  <TableRow
                    key={index}
                    onClick={() =>
                      navigate("/scanResult", {
                        state: { ...data, type : data.type },
                      })
                    }
                    style={{ cursor: "pointer" }}
                  >
                    <TableCell>{data.type}</TableCell>
                    <TableCell>{data.scan_time || "NULL"}</TableCell>
                    <TableCell>{data.ip || "NULL"}</TableCell>
                    <TableCell>{formatList(data.open_ports, 10)}</TableCell>
                    <TableCell>
                      {formatList(data.open_or_filtered, 10)}
                    </TableCell>
                    <TableCell>{data.scan_type || "NULL"}</TableCell>
                    <TableCell>{data.port || "NULL"}</TableCell>
                    <TableCell>{data.state || "NULL"}</TableCell>
                    <TableCell>{data.service || "NULL"}</TableCell>
                    <TableCell>{data.version || "NULL"}</TableCell>
                    <TableCell>{data.cpe || "NULL"}</TableCell>
                    <TableCell>{data.info || "NULL"}</TableCell>
                    <TableCell style={{ whiteSpace: "pre-wrap" }}>
                      {Array.isArray(data.cves) ? formatCVEs(data.cves) : "NULL"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {combinedData.length > itemsPerPage && (
          <Box sx={{ display: "flex", justifyContent: "center", marginTop: 2 }}>
            <Pagination
              count={Math.ceil(combinedData.length / itemsPerPage)}
              page={currentPage}
              onChange={handlePageChange}
              color="primary"
              variant="outlined"
              shape="rounded"
            />
          </Box>
        )}
      </div>
    </div>
  );
};

export default RecentScan;
