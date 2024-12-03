import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./App.css";

const ScanResult = () => {
  const location = useLocation();
  const data = location.state || {};  // 다른 페이지에서 전달받은 데이터

  const defaultData = { 
    ip: "Unknown", 
    open_ports: [], 
    open_or_filtered: [], 
    scan_type: "Unknown", 
    scan_time: "Unknown",
    additional_info: [],
  };

  // 타입에 따라 데이터를 통일
  const unifiedData = data.type === "Additional Information"
    ? { ...defaultData, ...data.additional_info, additional_info: data.additional_info.cves }
    : { ...defaultData, ...data };
  
  const [selectedMenu, setSelectedMenu] = useState("Basic Information"); // 선택된 메뉴 상태
  const [isOpenPortsVisible, setIsOpenPortsVisible] = useState(false);  // open_ports 펼치기/접기 상태
  const [isOpenOrFilteredVisible, setIsOpenOrFilteredVisible] = useState(false); // open_or_filtered 펼치기/접기 상태
  const navigate = useNavigate();

  const [expandedCves, setExpandedCves] = useState([]);

  // 토글 함수: 특정 CVE의 확장 상태를 토글
  const toggleCve = (index) => {
    setExpandedCves((prevExpanded) => {
      const updated = [...prevExpanded];
      updated[index] = !updated[index];
      return updated;
    });
  };

  const toggleOpenPorts = () => setIsOpenPortsVisible(!isOpenPortsVisible);
  const toggleOpenOrFiltered = () => setIsOpenOrFilteredVisible(!isOpenOrFilteredVisible);

  const formatList = (list, isVisible, toggleVisibility) => {
    if (!list || list.length === 0) return "[]";

    // 리스트가 10개 이상일 경우
    if (list.length > 10) {
      return (
        <>
          <span>{isVisible ? `[${list.join(", ")}]` : `[${list.slice(0, 10).join(", ")}, ...]`}</span>
          <button onClick={toggleVisibility} className="expand-button">
            {isVisible ? "접기" : "펼치기"}
          </button>
        </>
      );
    }

    return `[${list.join(", ")}]`;
  };

  const renderContent = () => {
    switch (selectedMenu) {
      case "Basic Information":
        return (
          <ul className="scan-result-container">
            <li>
              <strong>IP:</strong>
              <span className={unifiedData.ip ? "" : "empty"}>
                {unifiedData.ip || "Unknown"}
              </span>
            </li>
            <li>
              <strong>Open Ports:</strong>
              <span>{formatList(unifiedData.open_ports, isOpenPortsVisible, toggleOpenPorts)}</span>
            </li>
            <li>
              <strong>Open or Filtered Ports:</strong>
              <span>{formatList(unifiedData.open_or_filtered, isOpenOrFilteredVisible, toggleOpenOrFiltered)}</span>
            </li>
            <li>
              <strong>Scan Type:</strong>
              <span className={unifiedData.scan_type ? "" : "empty"}>
                {unifiedData.scan_type || "Unknown"}
              </span>
            </li>
            <li>
              <strong>Scan Time:</strong>
              <span className={unifiedData.scan_time ? "" : "empty"}>
                {unifiedData.scan_time || "Unknown"}
              </span>
            </li>
          </ul>
        );
  
      case "Additional Information":
        return (
          <div className="additional-info-container">
            <h3>추가 정보</h3>
            {unifiedData.additional_info && unifiedData.additional_info.length > 0 ? (
              <ul>
                {unifiedData.additional_info.map((info, index) => (
                  <li key={index}>
                    <strong>Port {info.port}:</strong>{" "}
                    {info.service || "Unknown"}
                    {info.cves && info.cves.length > 0 && (
                      <ul>
                        {info.cves.map((cve, cveIndex) => (
                          <li key={cveIndex}>
                            <button
                              onClick={() => toggleCve(cveIndex)}
                              style={{
                                background: "none",
                                border: "none",
                                color: "blue",
                                cursor: "pointer",
                                textDecoration: "underline",
                              }}
                            >
                              {expandedCves[cveIndex] ? "접기 ▲" : "펼치기 ▼"}
                            </button>
                            {expandedCves[cveIndex] && (
                              <div style={{ marginLeft: "1rem" }}>
                                <strong>{cve.cve_id}</strong> - {cve.summary}
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <span>추가 정보가 없습니다.</span>
            )}
          </div>
        );
  
      default:
        return null;
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
            <li
              className={selectedMenu === "Basic Information" ? "active" : ""}
              onClick={() => setSelectedMenu("Basic Information")}
            >
              기본 정보
            </li>
            <li
              className={selectedMenu === "Additional Information" ? "active" : ""}
              onClick={() => setSelectedMenu("Additional Information")}
            >
              추가 정보
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
