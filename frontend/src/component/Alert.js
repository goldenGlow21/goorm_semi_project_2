import Swal from "sweetalert2";


// 로딩창 표시
export const loadingAlert = (text) => { 
    Swal.fire({
        title: "Processing...",
        text: "Please wait while we scan your data.",
        allowOutsideClick: false,
        didOpen: () => { Swal.showLoading(); }  // 로딩 애니메이션 표시
    }); 
};

export const successAlert = (title = "Success!", text = "Operation completed successfully.") => {
    Swal.fire({
        icon: "success",
        title,
        text,
        confirmButtonText: "OK",
    });
};

export const errorAlert = (text) => {
    Swal.fire({
        icon: "error",
        title: "Oops...",
        text: "Failed to fetch scan results. Please try again later.",
      });
};
