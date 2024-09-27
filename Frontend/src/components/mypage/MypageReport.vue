<template>
  <div>
    <Mypage />
    <div class="table-responsive">
      <table class="table table-nowrap table-flush">
        <thead>
          <tr>
            <th scope="col">
              <div class="d-flex align-items-center gap-2 ps-1">
                <div class="text-base">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" />
                  </div>
                </div>
                <span>시뮬레이션 리포트 결과</span>
              </div>
            </th>
            <th scope="col">자본</th>
            <th scope="col">분류</th>
            <th scope="col">추천위치</th>
            <th scope="col">날짜</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="report in reports" :key="report.id">
            <td>
              <div class="d-flex align-items-center gap-3 ps-1">
                <div class="text-base">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" />
                  </div>
                </div>
                <div
                  class="icon icon-shape w-rem-10 h-rem-10 rounded-circle text-sm bg-primary bg-opacity-25 text-tertiary"
                >
                  <i class="bi bi-file-fill"></i>
                </div>
                <div>
                  <span class="d-block text-heading fw-bold">{{
                    report.title
                  }}</span>
                </div>
              </div>
            </td>
            <td>
              <a class="text-current" href="#">{{ report.capital }}</a>
            </td>
            <td>{{ report.category }}</td>
            <td>{{ report.location }}</td>
            <td>{{ report.date }}</td>
            <td class="text-end">
              <div class="dropdown">
                <a
                  class="text-muted"
                  href="#"
                  role="button"
                  data-bs-toggle="dropdown"
                  aria-haspopup="true"
                  aria-expanded="false"
                >
                  <i class="bi bi-three-dots-vertical"></i>
                </a>
                <div class="dropdown-menu dropdown-menu-end">
                  <a href="#!" class="dropdown-item">Action</a>
                  <a href="#!" class="dropdown-item">Another action</a>
                  <a href="#!" class="dropdown-item">Something else here</a>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';

import Mypage from '@/pages/mypage/Report.vue';

const reports = ref([
  {
    id: 1,
    title: '7번째 리포트',
    capital: '5억',
    category: '편의점',
    location: '강남',
    date: '2024-09-13',
  },
  {
    id: 'id2',
    title: '6번째 리포트',
    capital: '3억',
    category: '카페',
    location: '신촌',
    date: '2024-08-12',
    status: '',
  },
  {
    id: 'id3',
    title: '5번째 리포트',
    capital: '4억',
    category: '식당',
    location: '이태원',
    date: '2024-08-25',
    status: '',
  },
  {
    id: 'id4',
    title: '4번째 리포트',
    capital: '6억',
    category: '헬스장',
    location: '홍대',
    date: '2024-09-01',
    status: '',
  },
  {
    id: 'id5',
    title: '3번째 리포트',
    capital: '2억',
    category: '서점',
    location: '여의도',
    date: '2024-09-05',
    status: '',
  },
  {
    id: 'id6',
    title: '2번째 리포트',
    capital: '7억',
    category: '영화관',
    location: '종로',
    date: '2024-09-10',
    status: '',
  },
  {
    id: 'id6',
    title: '1번째 리포트',
    capital: '7억',
    category: '영화관',
    location: '종로',
    date: '2024-09-10',
    status: '',
  },
]);
</script>
