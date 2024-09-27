<template>
<div class="mb-10">
    <div class="container">
    <h2 style="font-weight: bold" class="mb-5">커뮤니티</h2>
    </div>
    <BoardList :showPagination="false" :showSearch="false" :showCreateButton="false" />
</div>
</template>

<script setup>
import BoardList from '@/pages/community/BoardList.vue';
</script>

<style></style>
