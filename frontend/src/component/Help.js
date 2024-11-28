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
                        <li>취약점 탐지: Description for option 1</li>
                        <li>침투 테스트: Description for option 2</li>
                        <li>기타 옵션: Description for option 1</li>
                        <li>속도 옵션: Description for option 1</li>
                    </ul>
            </Typography>
          </Popover>
        </div>
    );
};

export default BasicHelpPopover;