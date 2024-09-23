<template>
  <div class="container">
    <div class="title">상권분석</div>
    <div class="row">
      <div class="col-6">
        <canvas id="bar-chart" style="height: 200px"></canvas>
      </div>
      <div class="col-6">
        <canvas id="doughnut-chart" style="height: 200px"></canvas>
      </div>
    </div>
    <div class="row">
      <div class="col-6">
        <canvas id="bar-chart2" style="height: 200px"></canvas>
      </div>
      <div class="col-6">
        <canvas id="bar-chart3" style="height: 200px"></canvas>
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
  top: 5%;
  font-size: 25px;
  font-weight: bold;
}

.container {
  padding: 0px 80px;
}
</style>
