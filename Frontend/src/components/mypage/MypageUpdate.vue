<template>
  <Mypage />
  <div class="container">
    <h1>개인정보 설정</h1>
    <hr />
    <h4>닉네임 변경</h4>
    <hr />
    <div class="row mb-3">
      <label for="inputEmail3" class="col-sm-2 col-form-label">새 닉네임</label>
      <div class="col-sm-6">
        <input type="text" class="form-control" />
      </div>
    </div>
    <hr />
    <h4>비밀번호 변경</h4>
    <hr />
    <div class="row mb-3">
      <label for="inputEmail3" class="col-sm-2 col-form-label"
        >현재 비밀번호</label
      >
      <div class="col-sm-6">
        <input type="text" class="form-control" />
      </div>
    </div>
    <div class="row mb-3">
      <label for="inputEmail3" class="col-sm-2 col-form-label"
        >새 비밀번호</label
      >
      <div class="col-sm-6">
        <input type="text" class="form-control" />
      </div>
    </div>
    <div class="row mb-3">
      <label for="inputEmail3" class="col-sm-2 col-form-label"
        >새 비밀번호 확인</label
      >
      <div class="col-sm-6">
        <input type="text" class="form-control" />
      </div>
      <div class="btn-cls">
        <button type="submit" class="btn btn-sm btn-neutral">cancel</button>
        <div class="btn-size"></div>
        <button type="submit" class="btn btn-sm btn-primary">save</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import Mypage from '@/pages/mypage/Mypage.vue';
</script>
