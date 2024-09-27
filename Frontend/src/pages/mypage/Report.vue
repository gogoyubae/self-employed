<template>
  <div>
    <MypageHeader />
    <div class="container">
      <ul class="nav nav-underline nav-fill">
        <li class="nav-item">
          <router-link
            class="nav-link"
            aria-current="page"
            to="mypageupdate"
            style="font-size: 18px"
            >개인정보 수정</router-link
          >
        </li>
        <li class="nav-item">
          <router-link
            class="nav-link active"
            aria-current="page"
            to="mypagereport"
            style="font-size: 18px"
            >마이리포트 확인</router-link
          >
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import MypageHeader from '@/components/mypage/MypageHeader.vue';
</script>

<style>
.btn-primary {
  margin: 0px 0px 0px 20px;
}
.btn-cls {
  display: flex;
  width: 18%;
  padding: 0.5% 0% 0% 20%;
}
.div-input {
  width: 40%;
}
</style>
