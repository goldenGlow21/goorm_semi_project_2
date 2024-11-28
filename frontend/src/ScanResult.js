import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./App.css";

const ScanResult = () => {
  const location = useLocation();
  const data = location.state || {};

  const defaultData = { 
    IP: "Unknown", 
    open: [], 
    open_or_filtered: [], 
    scan_type: "Unknown", 
    scan_time: "Unknown" 
  };

  // 타입에 따라 데이터를 통일
  const unifiedData = data.type === "scanResults" || data.type === "recentScan" 
    ? { ...defaultData, ...data } 
    : defaultData;

  const [selectedMenu, setSelectedMenu] = useState("IP"); // 선택된 메뉴 상태
  const navigate = useNavigate();

  const renderContent = () => {
    switch (selectedMenu) {
      // 받을 json { IP : "192.168.1.1, open : [23, 44 ~~], open_or_filtered : [24, 25, 12], "scan_type": "tcp_connect", "scan_time": "2024-11-25T15:00:00Z" }
      // 여기에 추가 기능들 OS + 서비스, 취약점
      case "IP":
        return <p>{ unifiedData.IP || "IP 데이터가 없습니다."}</p>;
      case "Open Ports":
        return (
          <ul>
            { unifiedData.open.length > 0 
              ? unifiedData.open.map((port, index) => <li key={index}>{port}</li>)
              : <li>열린 포트가 없습니다.</li>
            }
          </ul>
        );
      case "Open or Filtered Ports":
        return (
          <ul>
            { unifiedData.open_or_filtered.length > 0
              ? unifiedData.open_or_filtered.map((port, index) => <li key={index}>{port}</li>)
              : <li>열리거나 필터링된 포트가 없습니다.</li>
            }
          </ul>
        );
      case "Scan Type":
        return <p>{unifiedData.scan_type || "스캔 타입 정보가 없습니다."}</p>;
      case "Scan Time":
        return <p>{unifiedData.scan_time || "스캔 시간 정보가 없습니다."}</p>;
      default:
        return <p>메뉴를 선택하세요.</p>;
    }
  };

  return (
    <div className="scan-result-container">
      {/* 상단 헤더 */}
      <header className="header">
        <div className="logo">
          <img src="/goormton.png" alt="Logo" />
        </div>
        <h1>Port Scanning Project</h1>
        <button className="mainboard-button" onClick={() => navigate("/")}>
          Main Board로 이동
        </button>
      </header>
      <div className="divider"></div>

      {/* 본문 */}
      <div className="content-wrapper">
        {/* 왼쪽 메뉴 */}
        <aside className="menu">
          <h2>스캔 결과 메뉴</h2>
          <ul>
            <li className={selectedMenu === "IP" ? "active" : ""} onClick={() => setSelectedMenu("IP")}>
              IP
            </li>
            <li className={selectedMenu === "Open Ports" ? "active" : ""} onClick={() => setSelectedMenu("Open Ports")}>
              열린 포트
            </li>
            <li className={selectedMenu === "Open or Filtered Ports" ? "active" : ""} onClick={() => setSelectedMenu("Open or Filtered Ports")}>
              열리거나 필터링된 포트
            </li>
            <li className={selectedMenu === "Scan Type" ? "active" : ""} onClick={() => setSelectedMenu("Scan Type")}>
              스캔 타입
            </li>
            <li className={selectedMenu === "Scan Time" ? "active" : ""} onClick={() => setSelectedMenu("Scan Time")}>
              스캔 시간
            </li>
          </ul>
        </aside>

        {/* 오른쪽 내용 */}
        <main className="content">
          <h2>스캔 결과</h2>
          {renderContent()}
        </main>
      </div>
    </div>
  );
};

export default ScanResult;