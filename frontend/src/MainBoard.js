import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { TextField, Menu, MenuItem, Typography, Button, Box } from "@mui/material";
import BasicHelpPopover from "./component/Help";
import "./App.css";
import { loadingAlert, successAlert, errorAlert } from "./component/Alert";
import Swal from "sweetalert2";

const categories = {
  category1: {
    label: "침투 테스트",
    options: [
      { id: "scan1", type: "tcp_fin", label: "TCP_FIN" },
      { id: "scan2", type: "null", label: "TCP_NULL" },
      { id: "scan3", type: "xmas", label: "TCP_XMAS" },
    ],
  },
  category2: {
    label: "취약점 탐지",
    options: [
      { id: "scan1", type: "tcp_connect", label: "TCP_CONNECT" },
      { id: "scan2", type: "tcp_fin", label: "TCP_FIN" },
      { id: "scan3", type: "null", label: "TCP_NULL" },
      { id: "scan4", type: "xmas", label: "TCP_XMAS" },
    ],
  },
  category3: {
    label: "네트워크 분석",
    options: [
      { id: "scan1", type: "tcp_connect", label: "TCP_CONNECT" },
      { id: "scan2", type: "tcp_syn", label: "TCP_SYN" },
      { id: "scan3", type: "udp", label: "UDP" },
      { id: "scan4", type: "ack", label: "TCP_ACK" },
    ],
  },
  category4: {
    label: "추가 정보 확인",
    options: [
      { id: "scan1", type:"additional_info", label:"추가 정보"},
    ]
  }
};

const MainBoard = () => {
  const [target_ip, setTargetIP] = useState("");
  const [target_start_port, setTargetStartPort] = useState("");
  const [target_end_port, setTargetEndPort] = useState("");
  const [scan_type, setScanType] = useState(null);  // 여기까지 제출 데이터
  const [scanResult, setScanResult] = useState();
  const [error, setError] = useState(null);
  const [showResult, setShowResult] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [activeCategory, setActiveCategory] = useState(null);

  const navigate = useNavigate();

  // 핸들러 함수
  const handleCategoryClick = (event, categoryKey) => {
    setAnchorEl(event.currentTarget);
    setActiveCategory(categoryKey);
  };

  const handleOptionSelect = (option) => {
    setScanType(option.type);
    handleClose();
  };

  const handleClose = () => {
    setAnchorEl(null);
    setActiveCategory(null);
  };

  const handleRecentScan = () => navigate("/recentScan");

  const handleScan = async () => {
    setShowResult(false);
    setError(null);

    // 로딩창
    loadingAlert("데이터 요청 중입니다...");

    const userData = {
      target_ip,
      target_start_port,
      target_end_port,
      scan_type
    };

    try {
      const response = await fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userData),
      });

      if (response.status === 200) {
        Swal.close(); // 로딩 창 닫음
        successAlert(); // 성공 창 렌더링

        const scanData = await response.json();
        setShowResult(true);
        setScanResult(scanData);

        // 데이터 구분 후 전달
        if (scan_type === "additional_info") {
          navigate("/scanResult", { state: { additional_info: scanData, type: "Additional Information" } });
        } else {
          navigate("/scanResult", { state: { ...scanData, type: "Basic Information" } });
        }
      } else {
        throw new Error("Failed to fetch scan results.");
      }
    } catch (err) {
      console.error("Error during scan:", err);
      setError("스캔 중 문제가 발생했습니다.");
      errorAlert("스캔 중 문제가 발생했습니다.");
    }
  };

  // 공통 스타일
  const textFieldStyles = {
    "& .MuiOutlinedInput-root": {
      "& fieldset": { borderColor: "blue" },
      "&:hover fieldset": { borderColor: "green" },
      "&.Mui-focused fieldset": { borderColor: "red" },
    },
  };

  return (
    <div className="container">
      {/* Header */}
      <header className="header">
        <div className="logo">
          <img src="/goormton.png" alt="Logo" />
        </div>
        <h1>Port Scanning Project</h1>
        <button className="recent-scan-button" onClick={handleRecentScan}>
          Recent Scan
        </button>
      </header>

      {/* Main Content */}
      <main className="main-content">
        {/* IP 입력 필드 */}
        <TextField
          className="input-box"
          type="text"
          placeholder="IP, 도메인을 입력하세요."
          onChange={(e) => setTargetIP(e.target.value)}
          sx={{
            ...textFieldStyles,
            "& input::placeholder": {
              color: "gray",
              opacity: 1,
            },
          }}
        />

        {/* Port 입력 필드 */}
        <div>
          <TextField
            className="input-box"
            type="number"
            placeholder="Start Port"
            value={target_start_port}
            onChange={(e) => setTargetStartPort(e.target.value)}
            style={{ marginRight: "10px" }}
            sx={{
              ...textFieldStyles,
              "& input::placeholder": {
                color: "gray",
                opacity: 1,
              },
            }}
          />
          <TextField
            className="input-box"
            type="number"
            placeholder="End Port"
            value={target_end_port}
            onChange={(e) => setTargetEndPort(e.target.value)}
            sx={{
              ...textFieldStyles,
              "& input::placeholder": {
                color: "gray",
                opacity: 1,
              },
            }}
        />
        </div>

        {/* 스캔 옵션 */}
        <Box className="options" sx={{ display: "flex", gap: 2, alignItems: "center" }}>
          {Object.entries(categories).map(([key, category]) => (
            <Box className="button-container" key={key}>
              <Button
                className="option-button"
                variant="contained"
                onClick={(e) => handleCategoryClick(e, key)}
              >
                {activeCategory === key ? `선택: ${scan_type || "없음"}` : category.label}
              </Button>
              <Menu
                anchorEl={anchorEl}
                open={activeCategory === key}
                onClose={handleClose}
              >
                {category.options.map((option) => (
                  <MenuItem key={option.id} onClick={() => handleOptionSelect(option)}>
                    {option.label}
                  </MenuItem>
                ))}
              </Menu>
            </Box>            
          ))}        
          <BasicHelpPopover />
        </Box>

        {/* 선택된 옵션 */}
        <Typography variant="body1" className="selected-option">
          Selected Option: {scan_type}
        </Typography>

        {/* 스캔 버튼 */}
        {!showResult && (
          <button className="scan-button" onClick={handleScan}>
            스캔 시작
          </button>
        )}

        {/* 스캔 결과 없으면 재스캔 */}
        {showResult && (
          <div className="scan-container">
            {error && (
              <div className="error-container">
                <p className="error">{error}</p>
                <button
                  className="retry-button"
                  onClick={() => setShowResult(false)}
                >
                  다시 스캔
                </button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>
          © 2024 goorm 정보보호 9회차 Semi Project<br />
          공동제작자: 임찬수 이종훈 양인규 정윤호 박성호
        </p>
      </footer>
    </div>
  );
};

export default MainBoard;
