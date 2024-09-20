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
  maintainAspectRatio: false,
  scales: {
    x: {
      grid: {
        color: 'rgba(255, 255, 255, 0.3)',
        lineWidth: 1,
      },
      ticks: {
        autoSkip: true,
        maxRotation: 0,
        minRotation: 0,
        padding: 10,
      },
    },
  },
  // 막대 두께 조정
  elements: {
    bar: {
      borderWidth: 2, // 막대 테두리 두께 조정
    },
  },
  // 막대 너비 및 카테고리 비율 조정
  barPercentage: 0.5, // 0.0 - 1.0 범위로 너비 조정
  categoryPercentage: 0.5, // 카테고리 내에서 막대 비율 조정
};

// doughnutOptions
export const doughnutOptions = {
  responsive: true,
  maintainAspectRatio: false, // false로 설정하여 CSS 높이 사용
};
