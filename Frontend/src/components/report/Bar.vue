<template>
  <div style="background-color: #f6f4f9">
    <div class="container pb-7">
      <div class="title">상권분석</div>
      <div class="row">
        <div class="col-6">
          <div class="chart-container">
            <div class="text-cont">
              <div class="chart-text">text aera</div>
            </div>
            <div class="p-5">
              <canvas id="bar-chart" style="height: 200px"></canvas>
            </div>
          </div>
        </div>

        <div class="col-6">
          <div class="chart-container">
            <div class="text-cont">
              <div class="chart-text">text aera</div>
            </div>
            <div class="p-5">
              <canvas id="doughnut-chart" style="height: 200px"></canvas>
            </div>
          </div>
        </div>
      </div>
      <div class="row">
        <div class="col-6">
          <div class="chart-container">
            <div class="text-cont">
              <div class="chart-text">text aera</div>
            </div>
            <div class="p-5">
              <canvas id="bar-chart2" style="height: 200px"></canvas>
            </div>
          </div>
        </div>
        <div class="col-6">
          <div class="chart-container">
            <div class="text-cont">
              <div class="chart-text">text aera</div>
            </div>
            <div class="p-5">
              <canvas id="bar-chart3" style="height: 200px"></canvas>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { Chart } from 'chart.js/auto';
import {
  data_bar,
  data_doughnut,
  barOptions,
  options,
} from '@/assets/js/chart.js';

let barChartInstance = ref(null); // 막대 차트 인스턴스
let doughnutChartInstance = ref(null); // 도넛 차트 인스턴스

onMounted(() => {
  const barCtx = document.getElementById('bar-chart').getContext('2d');
  const barCtx2 = document.getElementById('bar-chart2').getContext('2d');
  const barCtx3 = document.getElementById('bar-chart3').getContext('2d');
  const doughnutCtx = document
    .getElementById('doughnut-chart')
    .getContext('2d');

  // Chart.js를 사용하여 바 차트 생성
  barChartInstance.value = new Chart(barCtx, {
    type: 'bar',
    data: data_bar,
    options: barOptions,
  });
  barChartInstance.value = new Chart(barCtx2, {
    type: 'bar',
    data: data_bar,
    options: barOptions,
  });
  barChartInstance.value = new Chart(barCtx3, {
    type: 'bar',
    data: data_bar,
    options: barOptions,
  });

  // Chart.js를 사용하여 도넛 차트 생성
  doughnutChartInstance.value = new Chart(doughnutCtx, {
    type: 'doughnut',
    data: data_doughnut,
    options: options,
  });
});
</script>

<style scoped>
canvas {
  max-width: 100%;
  height: auto;
}

.title {
  padding: 5px 0px 1px 0px;
}

.container {
  padding: 0px 80px;
}
.chart-container {
  background-color: white;
  margin: 5px;
}
.text-cont {
  padding: 4% 15% 0%;
}
.chart-text {
  overflow-wrap: break-word; /* 단어가 길 경우 줄바꿈 */
  word-break: break-all; /* 모든 단어를 줄바꿈 */
  white-space: normal; /* 연속된 공백을 줄바꿈으로 처리 */
  height: 78px;
}
</style>
