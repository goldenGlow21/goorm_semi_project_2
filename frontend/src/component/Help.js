import React, { useState } from "react";
import { Popover, Typography, Button } from "@mui/material";
import "../App.css"

const BasicHelpPopover = () => {
    const [anchorEl, setAnchorEl] = useState(null);
    const handleClick = (e) => {
        setAnchorEl(e.currentTarget);
    };

    const handleClose = () => {
        setAnchorEl(null);
    };

    const open = Boolean(anchorEl);
    const id = open ? 'help' : undefined;
    
    return (
        <div>
          <Button
           aria-describedby={id}
           variant="contained"
           onClick={handleClick}
           className="help-button">
            Help
          </Button>
          <Popover
            id={id}
            open={open}
            anchorEl={anchorEl}
            onClose={handleClose}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'left',
            }}
          >
            <Typography sx={{ p: 2 }}>
                옵션에 대한 설명입니다.
                    <ul>
                        <li>침투 테스트: 속도 중요</li>
                        <li>취약점 탐지: 정확도 중요</li>
                        <li>네트워크 분석: 상세한 설명</li>
                        <li>추가 정보 확인: 포트의 서비스 정보, 버전, CVE 취약점</li>
                    </ul>
            </Typography>
          </Popover>
        </div>
    );
};

export default BasicHelpPopover;