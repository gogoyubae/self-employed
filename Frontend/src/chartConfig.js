export const data_bar = {
  labels: ['January', 'February', 'March', 'April', 'May', 'June'],
  datasets: [
    {
      label: 'Data One',
      backgroundColor: '#fcd752',
      data: [40, 20, 12, 39, 10, 120, 39, 80, 40, 20, 12, 11], // 'data_bar' 대신 'data'
    },
  ],
};

export const data_doughnut = {
  labels: ['VueJs', 'EmberJs', 'ReactJs', 'AngularJs'],
  datasets: [
    {
      backgroundColor: ['#41B883', '#E46651', '#00D8FF', '#DD1B16'],
      data: [40, 20, 80, 10],
    },
  ],
};
// barOptions
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
        // callback: function (value) {
        //   return value; // 원래 값으로 반환
        // },
      },
    },
  },
};

// doughnutOptions
export const doughnutOptions = {
  responsive: true,
  maintainAspectRatio: false, // false로 설정하여 CSS 높이 사용
};
