export const data_bar = {
  labels: ['January', 'February', 'March', 'April', 'May', 'June'],
  datasets: [
    {
      label: 'Data One',
      backgroundColor: '#fcd752',
      data: [40, 20, 12, 39, 10, 120], // 'data_bar' 대신 'data'
    },
  ],
};

export const data_doughnut = {
  labels: ['색1', '색2', '색3', '색4'],
  datasets: [
    {
      backgroundColor: ['#f6f4f9', '#fca3b9', '#fcd752', '#6184c6'],
      data: [40, 20, 80, 10],
    },
  ],
};

export const barOptions = {
  responsive: true,
  maintainAspectRatio: false, // CSS 높이 사용
  scales: {
    x: {
      grid: {
        color: 'rgba(255, 255, 255, 0.3)',
        lineWidth: 1,
      },
      ticks: {
        autoSkip: true, // 레이블 자동 생략
        maxRotation: 0, // 최대 회전 각도 (0도: 수평)
        minRotation: 0, // 최소 회전 각도 (0도: 수평)
        padding: 10, // 레이블과 x축 사이의 간격 (픽셀)
      },
    },
  },
  barThickness: 20,
};

export const options = {
  responsive: true,
  maintainAspectRatio: false,
};
